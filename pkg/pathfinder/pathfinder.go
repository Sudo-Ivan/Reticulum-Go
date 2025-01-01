package pathfinder

import "time"

type PathFinder struct {
	paths map[string]Path
}

type Path struct {
	NextHop     []byte
	Interface   string
	HopCount    byte
	LastUpdated int64
}

func NewPathFinder() *PathFinder {
	return &PathFinder{
		paths: make(map[string]Path),
	}
}

func (p *PathFinder) AddPath(destHash string, nextHop []byte, iface string, hops byte) {
	p.paths[destHash] = Path{
		NextHop:     nextHop,
		Interface:   iface,
		HopCount:    hops,
		LastUpdated: time.Now().Unix(),
	}
}

func (p *PathFinder) GetPath(destHash string) (Path, bool) {
	path, exists := p.paths[destHash]
	return path, exists
}
