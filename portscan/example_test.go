package portscan_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ilyaytrewq/postscan/portscan"
)

type exampleDialer struct{}

func (exampleDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func Example() {
	ports, err := portscan.List(80)
	if err != nil {
		log.Fatal(err)
	}
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
		portscan.WithDialer(exampleDialer{}),
	)
	if err != nil {
		log.Fatal(err)
	}

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, ports)
	if err != nil {
		log.Fatal(err)
	}
	for result := range results {
		fmt.Printf("%s %s\n", result.Host, result.State)
	}
	// Output:
	// 127.0.0.1 open
}

func ExampleScanner_ScanAll() {
	ports, err := portscan.ParsePorts("80,80")
	if err != nil {
		log.Fatal(err)
	}
	scanner, err := portscan.New(
		portscan.WithConnectTimeout(500*time.Millisecond),
		portscan.WithDialer(exampleDialer{}),
	)
	if err != nil {
		log.Fatal(err)
	}

	results, err := scanner.ScanAll(context.Background(),
		[]string{"127.0.0.1", "127.0.0.1"}, ports)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d result: %s\n", len(results), results[0].State)
	// Output:
	// 1 result: open
}

func ExampleParsePorts() {
	ports, err := portscan.ParsePorts("443, 22, 80, 8000-8002, 80")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ports, ports.Len())

	_, badPort := portscan.ParsePorts("http")
	fmt.Println(errors.Is(badPort, portscan.ErrInvalidPort))

	_, reversedRange := portscan.ParsePorts("1000-1")
	fmt.Println(errors.Is(reversedRange, portscan.ErrInvalidPortRange))
	// Output:
	// 22,80,443,8000-8002 6
	// true
	// true
}

func ExampleUnion() {
	web, err := portscan.List(80, 443, 8080)
	if err != nil {
		log.Fatal(err)
	}
	high, err := portscan.Range(8000, 8003)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(portscan.Union(web, high))
	// Output:
	// 80,443,8000-8003,8080
}

func ExampleRange() {
	if _, err := portscan.Range(0, 1024); err != nil {
		fmt.Println(errors.Is(err, portscan.ErrInvalidPort), err)
	}
	// Output:
	// true portscan: invalid port: 0
}

func ExampleTargetError() {
	scanner, err := portscan.New(portscan.WithDialer(exampleDialer{}))
	if err != nil {
		log.Fatal(err)
	}
	ports, err := portscan.List(80)
	if err != nil {
		log.Fatal(err)
	}

	results, err := scanner.Scan(context.Background(), []string{"192.0.2.1", "not a host"}, ports)
	fmt.Println(results == nil)

	var target *portscan.TargetError
	if errors.As(err, &target) {
		fmt.Printf("rejected %q\n", target.Target)
	}
	// Output:
	// true
	// rejected "not a host"
}

func ExampleState_MarshalText() {
	data, err := json.Marshal(struct {
		State portscan.State `json:"state"`
	}{State: portscan.StateClosed})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
	// Output:
	// {"state":"closed"}
}
