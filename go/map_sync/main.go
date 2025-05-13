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

var debug bool = false

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

	if MapUpdater(_type).String() == "UPDATE" {
		n.fentryObjs.HashMap.Update(key, value, ebpf.UpdateAny)
		log.Printf("Client updated key %d to value %d", key, value)
	} else if MapUpdater(_type).String() == "DELETE" {
		n.fentryObjs.HashMap.Delete(key)
		log.Printf("Client deleted key %d", key)
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
	flag.Parse()
	address := *serverIP + ":" + fmt.Sprint(*serverPort)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fentryObjs := fentryObjects{}
	if err := loadFentryObjects(&fentryObjs, nil); err != nil {
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

	// ---------------------- Batching setup ----------------------
	eventChan := make(chan *MapData, 1000)
	batchInterval := 10 * time.Second
	var batch []*MapData
	var mu = &sync.Mutex{}

	// Ringbuf reader goroutine (producer)
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

	// Batch processor goroutine (consumer)
	go func() {
		ticker := time.NewTicker(batchInterval)
		defer ticker.Stop()

		for {
			select {
			case ev := <-eventChan:
				mu.Lock()
				batch = append(batch, ev)
				mu.Unlock()

			case <-ticker.C:
				mu.Lock()
				toSend := batch
				batch = nil
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
					if debug {
						log.Printf("Map ID: %d", e.MapID)
						log.Printf("Name: %s", string(e.Name[:]))
						log.Printf("PID: %d", e.PID)
						log.Printf("Update Type: %s", e.UpdateType.String())
						log.Printf("Key: %d", e.Key)
						log.Printf("Value: %d", e.Value)
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					_, err := client.SetValue(ctx, &ValueRequest{
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

	// Block main thread forever
	select {}
}
