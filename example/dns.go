package example

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

type ExampleSolver struct {
	sync.RWMutex
}

func NewExampleSolver() *ExampleSolver {
	return &ExampleSolver{}
}

// Comment out handleDNSRequest if unused:
// func (e *ExampleSolver) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
//	// ...
// }

func (e *ExampleSolver) addDNSAnswer(q dns.Question, msg *dns.Msg, req *dns.Msg) error {
	switch q.Qtype {
	// Return a specific A record IP for A10 Networks (adjust IP as needed)
	case dns.TypeA:
		rr, err := dns.NewRR(q.Name + " 5 IN A 192.168.1.1")
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, rr)
		return nil

	// TXT records are used for ACME dns-01 challenges
	case dns.TypeTXT:
		// Use the global txtRecords map.
		if txt, ok := txtRecords[q.Name]; ok {
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN TXT \"%s\"", q.Name, txt))
			if err != nil {
				return err
			}
			msg.Answer = append(msg.Answer, rr)
		}
		return nil

	// NS records for authoritative lookups, using an A10 Networks NS zone name
	case dns.TypeNS:
		rr, err := dns.NewRR(fmt.Sprintf("%s 5 IN NS ns.a10networks.invalid.", q.Name))
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, rr)
		return nil

	// SOA record specifying an A10 Networks zone
	case dns.TypeSOA:
		rr, err := dns.NewRR(fmt.Sprintf("ns.a10networks.invalid. 5 IN SOA ns.a10networks.invalid. hostmaster.a10networks.invalid. 2023100101 7200 3600 1209600 300"))
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, rr)
		return nil

	default:
		return fmt.Errorf("unimplemented record type %v", q.Qtype)

	}
}
