package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type Config fentry ../../bpf/fentry/fentry.c -cflags "-I../../vmlinux.h/include/x86"

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var debug bool
var dbglog = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)

func dlogf(format string, v ...any) {
	if debug {
		dbglog.Printf(format, v...)
	}
}

var kasp = keepalive.ServerParameters{
	MaxConnectionIdle: 30 * time.Second,
	Time:              5 * time.Second,
	Timeout:           1 * time.Second,
}

type Node struct {
	UnimplementedSyncServiceServer
	fentryObjs fentryObjects
}

func (n *Node) SetValue(ctx context.Context, in *ValueRequest) (*Empty, error) {
	value := in.GetValue()
	key := in.GetKey()
	_type := in.GetType()

	switch MapUpdater(_type).String() {
	case "UPDATE":
		n.fentryObjs.HashMap.Update(key, value, ebpf.UpdateAny)
		dlogf("Client updated key %d to value %d", key, value)
	case "DELETE":
		n.fentryObjs.HashMap.Delete(key)
		dlogf("Client deleted key %d", key)
	}

	return &Empty{}, nil
}

func startServer(node *Node, port string) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.KeepaliveParams(kasp))
	RegisterSyncServiceServer(s, node)

	log.Printf("Server is running at %s", port)
	if err := s.Serve(l); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	serverIP := flag.String("ip", "localhost", "Server IP address of the peer (to sync to)")
	serverPort := flag.Int("port", 50051, "Current host listen port")
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.Parse()
	address := *serverIP + ":" + fmt.Sprint(*serverPort)

	if debug {
		log.Println("Debug mode enabled")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fentryObjs := fentryObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}
	if err := loadFentryObjects(&fentryObjs, opts); err != nil {
		log.Fatal(err)
	}
	defer fentryObjs.Close()

	fUpdate, err := link.AttachTracing(link.TracingOptions{
		Program: fentryObjs.fentryPrograms.BpfProgKernHmapupdate,
	})
	if err != nil {
		log.Fatalf("opening htab_map_update_elem fentry: %s", err)
	}
	defer fUpdate.Close()

	fDelete, err := link.AttachTracing(link.TracingOptions{
		Program: fentryObjs.fentryPrograms.BpfProgKernHmapdelete,
	})
	if err != nil {
		log.Fatalf("opening htab_map_delete_elem fentry: %s", err)
	}
	defer fDelete.Close()

	var key uint32 = 0
	config := fentryConfig{
		HostPort: uint16(*serverPort),
		HostPid:  uint64(os.Getpid()),
	}
	err = fentryObjs.fentryMaps.MapConfig.Update(&key, &config, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to update the map: %v", err)
	}

	go startServer(&Node{fentryObjs: fentryObjs}, ":"+fmt.Sprint(*serverPort))

	rd, err := ringbuf.NewReader(fentryObjs.MapEvents)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	eventChan := make(chan *MapData, 1000)
	batchInterval := 2 * time.Second
	var batchMap = make(map[uint32]*MapData)
	var mu = &sync.Mutex{}

	// Ringbuf reader (producer)
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("Ringbuf read error: %v", err)
				continue
			}
			event := (*MapData)(unsafe.Pointer(&record.RawSample[0]))
			eventChan <- event
		}
	}()

	// Batch processor (consumer)
	go func() {
		ticker := time.NewTicker(batchInterval)
		defer ticker.Stop()

		for {
			select {
			case ev := <-eventChan:
				mu.Lock()
				batchMap[ev.Key] = ev
				mu.Unlock()

			case <-ticker.C:
				mu.Lock()
				toSend := make([]*MapData, 0, len(batchMap))
				for _, v := range batchMap {
					toSend = append(toSend, v)
				}
				batchMap = make(map[uint32]*MapData)
				mu.Unlock()

				if len(toSend) == 0 {
					continue
				}

				conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					log.Printf("Failed to connect to peer: %v", err)
					continue
				}
				client := NewSyncServiceClient(conn)

				for _, e := range toSend {
					dlogf("Map ID: %d", e.MapID)
					dlogf("Name: %s", string(e.Name[:]))
					dlogf("PID: %d", e.PID)
					dlogf("Update Type: %s", e.UpdateType.String())
					dlogf("Key: %d", e.Key)
					dlogf("Value: %d", e.Value)

					ctx, cancel := context.WithTimeout(context.Background(), time.Second)

					key := uint32(e.Key)
					value := uint32(e.Value)

					switch MapUpdater(e.UpdateType).String() {
					case "UPDATE":
						if err := fentryObjs.HashMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
							log.Printf("Local update failed: %v", err)
						} else {
							dlogf("Locally updated key %d to value %d", key, value)
						}
					case "DELETE":
						if err := fentryObjs.HashMap.Delete(&key); err != nil {
							log.Printf("Local delete failed: %v", err)
						} else {
							dlogf("Locally deleted key %d", key)
						}
					}

					_, err = client.SetValue(ctx, &ValueRequest{
						Key:   int32(e.Key),
						Value: int32(e.Value),
						Type:  int32(e.UpdateType),
						Mapid: int32(e.MapID),
					})
					cancel()
					if err != nil {
						log.Printf("Could not set value on peer: %v", err)
					}
				}
			}
		}
	}()

	select {} // block forever
}
