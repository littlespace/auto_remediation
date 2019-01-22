package executor

import (
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"github.com/streadway/amqp"
	"time"
)

const (
	exchangeName = "alerts"
	exchangeType = "direct"
	routingKey   = "alerts"
)

type IncidentInfo struct {
	Description string    `json:"description"`
	Entity      string    `json:"entity"`
	Device      string    `json:"device"`
	Site        string    `json:"site"`
	Owner       string    `json:"owner"`
	Team        string    `json:"team"`
	Tags        []string  `json:"tags"`
	StartTime   time.Time `json:"start_time"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
}

type Incident struct {
	Name    string         `json:"name"`
	Id      int64          `json:"id"`
	Infos   []IncidentInfo `json:"infos"`
	AddedAt time.Time      `json:"added_at"`
}

type IncidentQueue interface {
	Register(chan Incident)
	Shutdown() error
}

type AmqpQueue struct {
	Name    string
	conn    *amqp.Connection
	channel *amqp.Channel
	done    chan bool
	sendTo  chan Incident
}

func NewQueue(name string, addr, user, pass string) (*AmqpQueue, error) {
	uri := fmt.Sprintf("amqp://%s:%s@%s", user, pass, addr)
	q := &AmqpQueue{
		Name: name, done: make(chan bool),
	}
	var err error
	if q.conn, err = amqp.Dial(uri); err != nil {
		return nil, fmt.Errorf("Error dialing amqp server: %v", err)
	}
	if q.channel, err = q.conn.Channel(); err != nil {
		return nil, fmt.Errorf("Error getting amqp channel: %v", err)
	}
	if err = q.channel.ExchangeDeclare(
		exchangeName, // name of the exchange
		exchangeType, // type
		false,        // durable
		false,        // delete when complete
		false,        // internal
		false,        // noWait
		nil,          // arguments
	); err != nil {
		return nil, fmt.Errorf("Error declaring Exchange: %v", err)
	}
	queue, err := q.channel.QueueDeclare(
		name,  // name
		false, // durable
		false, // delete when usused
		true,  // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return nil, fmt.Errorf("Error declaring queue: %v", err)
	}
	if err = q.channel.QueueBind(
		queue.Name,   // queue name
		routingKey,   // routing key
		exchangeName, // exchange
		false,
		nil,
	); err != nil {
		return nil, fmt.Errorf("Error binding a queue: %v", err)
	}
	msgs, err := q.channel.Consume(
		q.Name, // queue
		"",     // consumer
		false,  // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to get msg chan : %v", err)
	}
	go q.recv(msgs)
	glog.Infof("Connected to AMQP server: %v. QName: %s", addr, name)
	return q, nil
}

func (q *AmqpQueue) Register(sendTo chan Incident) {
	q.sendTo = sendTo
}

func (q *AmqpQueue) Shutdown() error {
	// will close() the deliveries channel
	if err := q.channel.Cancel("", true); err != nil {
		return fmt.Errorf("Consumer cancel failed: %s", err)
	}

	if err := q.conn.Close(); err != nil {
		return fmt.Errorf("AMQP connection close error: %s", err)
	}
	// wait for recv() to exit
	<-q.done
	return nil
}

func (q *AmqpQueue) recv(msgs <-chan amqp.Delivery) {
	for m := range msgs {
		i := Incident{}
		err := json.Unmarshal(m.Body, &i)
		if err != nil {
			glog.Errorf("Error decoding incident: %v", err)
			continue
		}
		// TODO: Ack only after work is done
		m.Ack(false)
		q.sendTo <- i
	}
	q.done <- true
}
