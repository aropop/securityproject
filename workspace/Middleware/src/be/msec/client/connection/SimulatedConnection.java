/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package be.msec.client.connection;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.net.Socket;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadT1Client;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;



public class SimulatedConnection implements IConnection {
	private CadT1Client cad;
	private Socket sock;
	private int port;

	public SimulatedConnection(){
		port=9025;
	}

	public void setPort(int i){
		port=i;
	}

	public void connect() throws CardConnectException {
		try {
			sock = new Socket("localhost", port);
			sock.setTcpNoDelay(true);
			BufferedInputStream is = new BufferedInputStream(sock.getInputStream());
			BufferedOutputStream os = new BufferedOutputStream(sock.getOutputStream());
			cad = new CadT1Client(is,os);
			cad.powerUp();
		} catch(Exception e) {
			throw new CardConnectException(e.getMessage());
		}
	}

	public void close() throws CardConnectException {
		try {
			cad.powerDown();
			sock.close();
			cad.close();
		} catch(Exception e) {
			throw new CardConnectException(e.getMessage());
		}
	}

	public ResponseAPDU transmit(CommandAPDU apdu) throws CardConnectException {
		Apdu a = new Apdu();
		a.command[0] = (byte)apdu.getCLA();
		a.command[1] = (byte)apdu.getINS();
		a.command[2] = (byte)apdu.getP1();
		a.command[3] = (byte)apdu.getP2();
		a.setDataIn(apdu.getData());
		a.Le = apdu.getNe();
		try {
			cad.exchangeApdu(a);
			return new ResponseAPDU(a.getResponseApduBytes());	
		} catch(Exception e) {
			throw new CardConnectException(e.getMessage());
		}
	}

}

