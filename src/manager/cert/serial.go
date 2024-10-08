package cert

import (
	"fmt"
	"log"
	"math/big"
	"os"
)

func (c *Certificate) GetSerial(incr bool) big.Int {
	path := c.Path + "/serial"
	log.Println("Checking if serial file exists: ", path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return c.NewSerial()
	}

	log.Println("Reading serial file: ", path)
	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}

	var serial big.Int
	fmt.Fscan(file, &serial)
	file.Close()

	log.Println("Serial: ", serial.Text(10))

	if incr {
		serial.Add(&serial, big.NewInt(1))
		log.Println("Incremented serial: ", serial.Text(10))
		file, err := os.OpenFile(path, os.O_RDWR, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		file.WriteString(serial.Text(10))
	}

	return serial
}

func (c *Certificate) IncrSerial() big.Int {
	return c.GetSerial(true)
}

func (c *Certificate) NewSerial() big.Int {
	path := c.Path + "/serial"
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	log.Println("Creating new serial file: ", path)
	file.WriteString(fmt.Sprintf("%d", 1000))

	return *big.NewInt(1000)
}
