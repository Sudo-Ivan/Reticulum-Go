package announce

type Handler interface {
	AspectFilter() []string
	ReceivedAnnounce(destHash []byte, identity interface{}, appData []byte) error
	ReceivePathResponses() bool
}
