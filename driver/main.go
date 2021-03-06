package main

import (
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
)

func main() {
	fmt.Println("driver 1111xxxx")
	// create controller
	client, err := wgctrl.New()
	if err != nil {
		fmt.Println("driver 2222")
		if os.IsNotExist(err) {
			fmt.Println("driver 3333")
			panic(fmt.Errorf("wgctrl is not available on this system"))
		}
		fmt.Println("driver 4444")
		panic(fmt.Errorf("failed to open wgctl client: %v", err))
	}
	fmt.Println("driver 5555")
	d, e := client.Devices()
	fmt.Println(d)
	fmt.Println(e)
	/*defer func() {
		if err != nil {
			if err := client.Close(); err != nil {
				panic(fmt.Errorf("Failed to close client %v", err))
			}
			client = nil
		}
	}()*/

	// configure the device. still not up
	port := 19860
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		fmt.Println("driver 66666")
		panic(fmt.Errorf("error generating private key: %v", err))
	}
	pub := priv.PublicKey()
	peerConfigs := make([]wgtypes.PeerConfig, 0)
	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		FirewallMark: nil,
		ReplacePeers: true,
		Peers:        peerConfigs,
	}
	deviceName := "le-wg0"
	if err = client.ConfigureDevice(deviceName, cfg); err != nil {
		fmt.Println("driver 77777")
		panic(fmt.Errorf("failed to configure WireGuard device: %v", err))
	}
	fmt.Println("driver 888888")

	fmt.Printf("Created WireGuard %s with publicKey %s", deviceName, pub)
}
