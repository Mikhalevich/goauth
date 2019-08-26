package goauth

type LoginRequest struct {
	Time int64
}

type UnknownRequest struct {
	ID       int
	IP       string
	URL      string
	Requests []LoginRequest
}

func (ur *UnknownRequest) RequestsAfter(ut int64) int {
	count := 0
	for _, r := range ur.Requests {
		if r.Time > ut {
			count++
		}
	}
	return count
}

func NewUnknownRequest(ip, url string) *UnknownRequest {
	return &UnknownRequest{
		IP:       ip,
		URL:      url,
		Requests: make([]LoginRequest, 0),
	}
}
