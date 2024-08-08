package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

type syscallAggregator struct {
	mu         sync.Mutex
	counts     map[string]int
	period     time.Duration
	ticker     *time.Ticker
	stopSignal chan bool
}

func newSyscallAggregator(period time.Duration) *syscallAggregator {
	return &syscallAggregator{
		counts:     make(map[string]int),
		period:     period,
		ticker:     time.NewTicker(period),
		stopSignal: make(chan bool),
	}
}

func (sa *syscallAggregator) start() {
	go func() {
		for {
			select {
			case <-sa.ticker.C:
				sa.emitJSON()
				sa.counts = make(map[string]int)
			case <-sa.stopSignal:
				sa.ticker.Stop()
				return
			}
		}
	}()
}

func (sa *syscallAggregator) stop() {
	sa.stopSignal <- true
}

func (sa *syscallAggregator) addSyscall(syscallNr int) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	name, ok := syscalls.GetSyscallNameByNumber(syscallNr)
	if ok {
		sa.counts[name]++
	}
}

func (sa *syscallAggregator) emitJSON() {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	data, err := json.Marshal(sa.counts)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}

	fmt.Println(string(data))
}

func do(sa *syscallAggregator) error {
	const opPriority = 50000
	syscallCountOperator := simple.New("countSyscalls", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
		for _, d := range gadgetCtx.GetDataSources() {
			syscallNrF := d.GetField("syscall_nr")

			d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				syscallNr, _ := syscallNrF.Int32(data)
				sa.addSyscall(int(syscallNr))
				return nil
			}, opPriority)
		}
		return nil
	}))

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		"syscall_count:latest",
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			syscallCountOperator,
		),
	)

	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer runtime.Close()

	params := map[string]string{
		"operator.oci.verify-image": "false",
	}

	if err := runtime.RunGadget(gadgetCtx, nil, params); err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	return nil
}

func main() {
	aggregator := newSyscallAggregator(5 * time.Minute)
	aggregator.start()
	defer aggregator.stop()

	if err := do(aggregator); err != nil {
		fmt.Printf("Error running application: %s\n", err)
		os.Exit(1)
	}
}
