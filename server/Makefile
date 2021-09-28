.PHONY: install clean

package_name = ssl_server
flags = -lssl -lcrypto
cert = cert.pem

install: ${package_name}.c
	gcc -Wall -o ${package_name} ${package_name}.c ${flags}
	openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ${cert} -out ${cert} -batch
clean:
	rm -rf ${package_name} ${cert}.pem

reinstall: clean install