package announce

type Handler interface {
	ReceivedAnnounce(destHash []byte, identity interface{}, appData []byte) error
}
