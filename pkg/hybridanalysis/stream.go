package hybridanalysis

import (
	"github.com/mpkondrashin/mstream/pkg/sleeper"
)

type SamplesStream struct {
	client      *Client
	sleeper     *sleeper.Sleeper
	data        *ListLatest
	sampleCount int
}

func NewSamplesStream(client *Client, sleeper *sleeper.Sleeper) *SamplesStream {
	return &SamplesStream{
		client:  client,
		sleeper: sleeper,
	}
}

func (s *SamplesStream) GetSample() (*ListLatestData, error) {
	if s.data == nil || s.sampleCount >= len(s.data.Data) {
		err := s.UpdateSamples()
		if err != nil {
			//log.Printf("EEE GetSample() %v", err)
			return nil, err
		}
	}
	d := &s.data.Data[s.sampleCount]
	s.sampleCount++
	return d, nil
}

func (s *SamplesStream) UpdateSamples() error {
	err := s.sleeper.SleepIfNeeded()
	if err != nil {
		//log.Printf("EEE UpdateSamples(): %v", err)
		return err
	}
	s.data, err = s.client.ListLatestSamples()
	if err != nil {
		return err
	}
	s.sampleCount = 0
	return nil
}
