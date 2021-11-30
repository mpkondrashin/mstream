package hybridanalysis

import (
	"errors"
	"os"
	"time"
)

var ErrShouldStop = errors.New("Stop signal received")

type Sleeper struct {
	lastTime          time.Time
	sleepInterval     time.Duration
	stopSignalChannel chan os.Signal
}

func NewPauser(sleepInterval time.Duration,
	stopSignalChannel chan os.Signal) *Sleeper {
	return &Sleeper{
		sleepInterval:     sleepInterval,
		stopSignalChannel: stopSignalChannel,
	}
}

func (s *Sleeper) TakeANap() error {
	nextQueryTime := s.lastTime.Add(s.sleepInterval)
	sleepTime := time.Until(nextQueryTime)
	select {
	case <-time.After(sleepTime):
	case <-s.stopSignalChannel:
		return ErrShouldStop
	}
	return nil
}

/*
	nextQueryTime := s.latestQueryTime.Add(s.pauseBetweenQueries)
	sleepTime := time.Until(nextQueryTime)
	time.Sleep(sleepTime)
*/

type SamplesStream struct {
	client              *Client
	latestQueryTime     time.Time
	pauseBetweenQueries time.Duration
	pauseFunc           PauseFunction
	data                *ListLatest
	sampleCount         int
}

func NewSamplesStream(client *Client, pauseBetweenQueries time.Duration, pauseFunc PauseFunction) *SamplesStream {
	return &SamplesStream{
		client:              client,
		pauseBetweenQueries: pauseBetweenQueries,
		pauseFunc:           pauseFunc,
	}
}

func (s *SamplesStream) GetSample() (*ListLatestData, error) {
	if s.data == nil {
		s.UpdateSamples()
	}
	if s.sampleCount >= len(s.data.Data) {

	}
}

func (s *SamplesStream) UpdateSamples() error {
	nextQueryTime := s.latestQueryTime.Add(s.pauseBetweenQueries)
	sleepTime := time.Until(nextQueryTime)
	time.Sleep(sleepTime)
	var err error
	s.data, err = s.client.ListLatestSamples()
	if err != nil {
		return err
	}
	s.sampleCount = 0
	return nil
}
