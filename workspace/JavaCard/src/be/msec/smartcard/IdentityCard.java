package be.msec.smartcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte GIVE_TIME = 0x25;
	private static final byte TIME_UPDATE = 0x26;
	private static final byte AUTHENTICATE_SP = 0x27;
	private static final byte CLOSE_CONNECTION = 0x28;
	private static final byte AUTHENTICATE_RESPONSE = 0x29;
	private static final byte AUTHENTICATE_CARD = 0x30;
	private static final byte GET_ATTRIBUTES = 0x31;
	private static final byte GET_REMAINING = 0x32;
	
	
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short SW_TIME_UPDATE_REQUIRED = 0x6302;
	private final static short SW_TIME_VERIFY_FAILED = 0x6303;
	private final static short SW_NOT_AUTHENTICATED = 0x6304;
	private final static short SW_CHALLENGE_WRONG = 0x6305;
	private final static short SW_UNAUTHORISED = 0x6306;
	private final static short SW_MORE_DATA = 0x6309;
	private final static short SW_BIG_DATA = 0x6308;
	
	private final static short CERT_NAME_OFFSET = 0;
	private final static short CERT_TYPE_OFFSET = 20;
	private final static short CERT_VALID_OFFSET = 21;
	private final static short CERT_PUB_EXP_OFFSET = 29;
	private final static short CERT_PUB_MOD_OFFSET = 32;
	private final static short CERT_SIGN_OFFSET = 96;

	private final static short LEN_NYM = 10;
	private final static short LEN_SYM_KEY = 16;
	private final static short LEN_SUBJECT = 20;
	private final static short LEN_CERT_DATA = CERT_SIGN_OFFSET;
	private final static short LEN_SIGN = 64;
	
	
	private static final byte TYPE_WEBSH = 0x00;
	private static final byte TYPE_EGOV = 0x03;
	private static final byte TYPE_SOC = 0x02;
	
	private byte[] serial = new byte[]{0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05};
	private byte[] time = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	
	private final static byte[] PUBLIC_KEY_G_MOD = Data.PUBLIC_KEY_G_MOD;
	private final static byte[] PUBLIC_KEY_G_EXP = Data.PUBLIC_KEY_G_EXP;
	private final static byte[] PUBLIC_KEY_CA_MOD = Data.PUBLIC_KEY_CA_MOD;
	private final static byte[] PUBLIC_KEY_CA_EXP  = Data.PUBLIC_KEY_CA_EXP;
	private final static byte[] PRIVATE_KEY_CO_MOD = Data.PRIVATE_KEY_CO_MOD;
	private final static byte[] PRIVATE_KEY_CO_EXP = Data.PRIVATE_KEY_CO_EXP;
	
	private final static byte[]CERT_CO = Data.CERT_CO;
	
	private static RSAPublicKey PUBLIC_KEY_CA = null;
	private static RSAPrivateKey PRIVATE_KEY_CO = null;
	private static RSAPublicKey PUBLIC_KEY_CO = null;
	
	private OwnerPIN pin;
	private byte[] subject;
	private byte type;
	private AESKey Ks;
	private final byte[] Ku;
	private boolean authenticated;
	private byte[] challenge;
	private RandomData rng;
	private byte[] remainingData;
	
	private final static byte[] name = Data.NAME; private final static short LEN_NAME = 30; // Assume ASCII encoding = 1 byte per char
	private final static byte[] address = Data.ADDRESS; private final static short LEN_ADDRESS = 50;
	private final static byte[] country = Data.COUNTRY; private final static short LEN_COUNTRY = 2;
	private final static byte[] birthday = Data.BIRTHDATE; private final static short LEN_BIRTHDAY = 8;
	private final static byte[] age = Data.AGE; private final static short LEN_AGE = 3; // Should be calculated
	private final static byte[] gender = Data.GENDER; private final static short LEN_GENDER = 1;
	private final static byte[] picture = Data.PICTURE; private final static short LEN_PICUTRE = 10000; // 10kb pictures

	
	private final byte[][] attributes; 
	
	// Each byte represents a right nym, name, address, country, birthdate, age, gender, picture
	private boolean[] EGOV_RIGHTS = new boolean[] {true, true, true, true, true, true, true, false};
	private boolean[] SOC_RIGHTS = new boolean[] {true, true, false, true, false, true, true, true};
	private boolean[] DEFAULT_RIGHTS = new boolean[] {true, false, false, false, false, true, false, false};
	private boolean[] WEBSH_RIGHTS = new boolean[] {true, true, true, true, false, false, false, false};
	
	
	
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE);
		
		
		// Set subject to null
		subject = null;
		Ks = null;
		Ku = JCSystem.makeTransientByteArray(LEN_SYM_KEY, JCSystem.CLEAR_ON_RESET);

		rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM); // Secure is unsupoorted in the simulator?
		rng.generateData(Ku, (short)0,(short)16);
		attributes = new byte[][] {Ku, name, address, country, birthday, age, gender, picture};
		authenticated = false;
		
		PUBLIC_KEY_CA = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		PUBLIC_KEY_CA.setExponent(PUBLIC_KEY_CA_EXP, (short)0, (short)PUBLIC_KEY_G_EXP.length);
		PUBLIC_KEY_CA.setModulus(PUBLIC_KEY_CA_MOD, (short)0, (short)PUBLIC_KEY_G_MOD.length);
		
		PRIVATE_KEY_CO = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
		PRIVATE_KEY_CO.setExponent(PRIVATE_KEY_CO_EXP, (short)0, (short)PRIVATE_KEY_CO_EXP.length);
		PRIVATE_KEY_CO.setModulus(PRIVATE_KEY_CO_MOD, (short)0, (short)PRIVATE_KEY_CO_MOD.length);
		
		PUBLIC_KEY_CO = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		PUBLIC_KEY_CO.setExponent(CERT_CO, (short)29, (short)PUBLIC_KEY_G_EXP.length);
		PUBLIC_KEY_CO.setModulus(CERT_CO, (short)32, (short)PUBLIC_KEY_G_MOD.length);
		
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new IdentityCard();
	}
	
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining()==0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet())
			return;
		
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
			
		case GIVE_TIME:
			giveTime(apdu);
			break;
			
		case TIME_UPDATE:
			timeUpdate(apdu);
			break;
			
		case AUTHENTICATE_SP:
			authenticateServiceProvider(apdu);
			break;
			
		case AUTHENTICATE_RESPONSE:
			authenticateServiceProviderResponse(apdu);
			break;
			
		case AUTHENTICATE_CARD:
			authenticateCard(apdu);
			break;
			
		case GET_ATTRIBUTES:
			getAttributes(apdu);
			break;
		
		case GET_REMAINING:
			// Clone to prevent overwriting
			byte[] newRData = new byte[(short)remainingData.length];
			Util.arrayCopy(remainingData, (short)0, newRData, (short)0, (short)remainingData.length);
			sendData(newRData, apdu);
			break;
			
		case 0x35:
			byte[] a = new byte[200];
			for(short i =0; i < (short) 200; i++) {
				a[i] = (byte) i;
			}
			sendData(a, apdu);
			break;
			
		case CLOSE_CONNECTION:
			//
			this.challenge = null;
			subject = null;
			Ks = null;
			authenticated = false;
			pin.reset();
			break;
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void sendData(byte[] data, APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setOutgoing();
		if((short) data.length > (short)255) {
			apdu.setOutgoingLength((short)255);
			Util.arrayCopy(data, (short)0, buffer, (short)0, (short)buffer.length);
			apdu.sendBytes((short)0, (short) buffer.length);
			apdu.sendBytesLong(data, (short) buffer.length, (short) (255 - buffer.length));
			remainingData = new byte[(short) data.length - (short)255];
			Util.arrayCopy(data, (short) 255, remainingData, (short) 0, (short) remainingData.length);
			ISOException.throwIt(SW_MORE_DATA);
		} else {
			if(buffer.length > data.length) {
				Util.arrayCopy(data, (short)0, buffer, (short)0, (short)data.length);
				apdu.setOutgoingLength((short) data.length);
				apdu.sendBytes((short)0, (short)data.length);
			} else {	
				apdu.setOutgoingLength((short)data.length);
				Util.arrayCopy(data, (short)0, buffer, (short)0, (short)buffer.length);
				apdu.sendBytes((short)0, (short) buffer.length);
				apdu.sendBytesLong(data, (short) buffer.length, (short) (data.length - buffer.length));
			}
			//apdu.sendBytesLong(data, (short)0, (short)data.length);			
		}
	}
	

	/*
	 * This method is used to authenticate the owner of the card using a PIN code.
	 */
	private void validatePIN(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		if(buffer[ISO7816.OFFSET_LC]==PIN_SIZE){
			//This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,PIN_SIZE)==false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
			else {
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) 1);
				apdu.sendBytesLong(new byte[]{0x00}, (short)0, (short)1);
			}
		}else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	
	/*
	 * This method checks whether the user is authenticated and sends
	 * the identity file.
	 */
	private void getSerial(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
		}
	}
	
	// Hello function
	private void giveTime(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// 86 400 000 -> 24 hour in miliseconds
		if(Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, time, (short) 0, (short) 8) == 1) {
			// Request time update
			 ISOException.throwIt(SW_TIME_UPDATE_REQUIRED);
		}
		sendData(new byte[]{}, apdu);
	}
	
	// If time is outdated
	private void timeUpdate(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		RSAPublicKey PKg = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		PKg.setExponent(PUBLIC_KEY_G_EXP, (short)0, (short)PUBLIC_KEY_G_EXP.length);
		PKg.setModulus(PUBLIC_KEY_G_MOD, (short)0, (short)PUBLIC_KEY_G_MOD.length);
		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		signature.init(PKg, Signature.MODE_VERIFY);
		boolean verify = signature.verify(buffer, ISO7816.OFFSET_CDATA, (short) 8,// time is a long so 8 size
				buffer, (short) (ISO7816.OFFSET_CDATA + 8), (short) LEN_SIGN); // SHA1 results in 160 bit = 20 bytes
		if(verify) {
			// Time is correct, add 24 hours
			add(buffer, (byte) 0x05, 
					new byte[] {0x00,0x00,0x00,0x00,0x05,0x26,0x5C,0x00}, (byte) 0x00,
					time, (byte) 0x00, (byte) 0x08);
			sendData(new byte[] {0x00}, apdu);
		} else {
			ISOException.throwIt(SW_TIME_VERIFY_FAILED);
		}
		
	}
	
	// If time is outdated
	private void authenticateServiceProvider(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte[] data = new byte[160];
		short currentOffset = (short)0;
		short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if (bytesLeft < (short)55) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
		short readCount = apdu.setIncomingAndReceive();
		while ( bytesLeft > 0){
			Util.arrayCopy(buffer, (short)5, data, (short)currentOffset, (short) (readCount));
			currentOffset = (short) (readCount);
		    bytesLeft -= readCount;
		    readCount = apdu.receiveBytes ( ISO7816.OFFSET_CDATA );
		}
		// Verify certifcate
		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		signature.init(PUBLIC_KEY_CA, Signature.MODE_VERIFY);
		if(!signature.verify(data, (short) 0, LEN_CERT_DATA, data, CERT_SIGN_OFFSET,  (short) LEN_SIGN)) {
			ISOException.throwIt(SW_VERIFICATION_FAILED);
			return;
		}
		
		// TODO verify date
		
		this.subject = new byte[LEN_SUBJECT];		
		Util.arrayCopy(data, CERT_NAME_OFFSET, this.subject, (short)0, LEN_SUBJECT);
		this.type = data[CERT_TYPE_OFFSET];
		
		// Generate symmetric key
		RandomData rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM); // secure random unsupported on simulator
		byte[] KsBytes = new byte[16];
		rng.generateData(KsBytes, (short)0,(short)16);
		this.Ks = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		Ks.setKey(KsBytes, (short) 0);
		
		// Create challenge
		this.challenge = new byte[12]; // 12 such that 20+12 =32 which is dividable by 16 for AES
		rng.generateData(challenge, (short)0, (short)12);
		
		// Create public key object
		RSAPublicKey publicKeySP = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		publicKeySP.setExponent(data, CERT_PUB_EXP_OFFSET, (short)PUBLIC_KEY_G_EXP.length);
		publicKeySP.setModulus(data, (short)CERT_PUB_MOD_OFFSET, (short)PUBLIC_KEY_G_MOD.length);
		
		// Sign symmetric key
		byte[] KsSigned = new byte[64];
		Cipher c = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		c.init(publicKeySP, Cipher.MODE_ENCRYPT);
		c.doFinal(KsBytes, (short)0, (short)16, KsSigned, (short)0);
		
		// Sign challenge and subject
		byte[] combined = new byte[challenge.length + subject.length];
		Util.arrayCopy(challenge, (short)0, combined, (short)0, (short)12);
		Util.arrayCopy(subject, (short)0, combined, (short)12, (short)10);
		byte[] combinedSigned = new byte[challenge.length+subject.length]; 
		c = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		c.init(this.Ks, Cipher.MODE_ENCRYPT);
		
		c.doFinal(combined, (short)0, (short)combined.length, combinedSigned, (short)0);		
		
		// Send responses
		byte[] response = new byte[KsSigned.length+combinedSigned.length];
		Util.arrayCopy(KsSigned, (short)0, response, (short)0, (short)KsSigned.length);
		Util.arrayCopy(combinedSigned, (short)0, response, (short)KsSigned.length, (short)combinedSigned.length);
		
		sendData(response, apdu);
	}
	
	// Second part of step 2
	public void authenticateServiceProviderResponse(APDU apdu) {
		if(Ks == null || subject == null) {
			ISOException.throwIt(SW_NOT_AUTHENTICATED);
			return;
		}
		byte[] buffer = apdu.getBuffer();
		byte[] challengeCompare = new byte[16];
		// For some black magical reason, this does not work with AES eventhough this alg is set at the service provider level
		Cipher cp = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false); 
		cp.init(Ks, Cipher.MODE_DECRYPT, new byte[16], (short) 0, (short) 16);
		cp.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) 16, challengeCompare, (short) 0);
		
		challengeCompare[1] = (byte) ~challengeCompare[1];
		if(Util.arrayCompare(challengeCompare, (short) 0, this.challenge, (short) 0, (short) 12) != 0) {
			ISOException.throwIt(SW_CHALLENGE_WRONG);
			return;
		}
		
		authenticated = true;
		
		sendData(new byte[]{}, apdu);
	}
	
	// Step 3
	public void authenticateCard(APDU apdu) {
		if(!authenticated) {
			ISOException.throwIt(SW_NOT_AUTHENTICATED);
			return;
		}
		// Decode challenge from SP
		byte[] buffer = apdu.getBuffer();
		byte[] challenge = new byte[16];
		Cipher cp = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cp.init(Ks, Cipher.MODE_DECRYPT, new byte[16], (short)0, (short)16);
		cp.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) 16, challenge, (short) 0);
		
		byte[] challengePlusAuth = new byte[20];
		Util.arrayCopy(challenge, (short)0, challengePlusAuth, (short) 0, (short) challenge.length);
		Util.arrayCopy(new byte[] {0x61, 0x75, 0x74, 0x68}, (short)0, challengePlusAuth, (short) challenge.length, (short) 4);
		MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		byte[] hash = new byte[64];
		md.doFinal(challengePlusAuth, (short) 0, (short) challengePlusAuth.length, hash, (short) 0);
		byte[] hash32 = new byte[32];
		Util.arrayCopy(hash, (short) 0, hash32, (short)0, (short)32);
		
		// Sign challenge plus "auth" with private key
		byte[] chAuSigned = new byte[64]; // 
		Signature sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		sign.init(PRIVATE_KEY_CO, Signature.MODE_SIGN);
		sign.sign(hash32, (short) 0, (short) hash32.length, chAuSigned, (short) 0);
		
		// Encrypt
		byte[] signedPlusCert = new byte[160+64]; 
		byte[] response = new byte[160+64]; 
		Util.arrayCopy(CERT_CO, (short)0, signedPlusCert, (short) 0, (short) CERT_CO.length); 
		Util.arrayCopy(chAuSigned, (short)0, signedPlusCert, (short) CERT_CO.length, (short) chAuSigned.length);
		cp.init(Ks,  Cipher.MODE_ENCRYPT);
		cp.doFinal(signedPlusCert, (short)0, (short) signedPlusCert.length, response, (short)0);
		
		sendData(response, apdu);
	}
	
	private void getAttributes(APDU apdu) {
		if(!authenticated) {
			ISOException.throwIt(SW_NOT_AUTHENTICATED);
			return;
		}
		
		if(!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			return;
		}
		
		//byte[] buffer = apdu.getBuffer();
		// Ignore query and return all he has rights to
		
		byte[] nym64 = new byte[64];
		byte[] nym = new byte[32];
		byte[] kuPlusSubject = new byte[LEN_SYM_KEY + LEN_SUBJECT];
		Util.arrayCopy(Ku, (short)0, kuPlusSubject, (short) 0, (short) Ku.length);
		Util.arrayCopy(subject, (short)0, kuPlusSubject, (short) Ku.length, (short) subject.length);
		
		MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		md.doFinal(kuPlusSubject,(short)0, (short)kuPlusSubject.length, nym64, (short)0);
		Util.arrayCopy(nym64, (short) 0, nym, (short)0, (short)32);
		 
		// Build data
		boolean[] rights;
		switch(type) {
		
		case TYPE_WEBSH:
			rights = WEBSH_RIGHTS;
			break;
			
		case TYPE_SOC:
			rights = SOC_RIGHTS;
			break;
			
		case TYPE_EGOV:
			rights = EGOV_RIGHTS;
			break;
			
		default:
			rights = DEFAULT_RIGHTS;
			break;
		
		}
		
		// Calculate data length
		short totLen = 0;
		for(short i = 0; i < (short) rights.length; i++) {
			boolean can = rights[i];
			if(can) {
				if(i == (short) 0){
					// Nym has special treatment
					totLen += (short) nym.length;
				} else {
					totLen += (short) attributes[i].length;					
				}
			}
		}
		
		// Create data array, nym is included
		short offset = 0;
		byte[] data;
		if((totLen % 16) == 0) {
			data = new byte[totLen];
		} else {
			data = new byte[totLen + (16 - (totLen % 16))];
		}
		for(short i = 0; i < (short) rights.length; i++) {
			boolean can = rights[i];
			if(can) {
				if(i == (short) 0) {
					Util.arrayCopy(nym, (short)0, data, (short) offset, (short) nym.length);
					offset += (short) nym.length;
				} else {
					Util.arrayCopy(attributes[i], (short)0, data, (short) offset, (short) attributes[i].length);
					offset += (short) attributes[i].length;
				}
			}
		}
		
		
		// encrypt data
		byte[] response = new byte[data.length]; 
		Cipher cp = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cp.init(Ks,  Cipher.MODE_ENCRYPT);
		cp.doFinal(data, (short)0, (short) data.length, response, (short)0);
		sendData(response, apdu);
	}
	
	
	// See https://stackoverflow.com/questions/36518553/javacard-applet-to-subtract-two-hexadecimal-array-of-byte
   public static boolean add(byte[] A, byte AOff, byte[] B, byte BOff, byte[] C, byte COff, byte len) {
        short result = 0;

        for (len = (byte) (len - 1); len >= 0; len--) {
            // add two unsigned bytes and the carry from the
            // previous byte computation.
            result = (short) (getUnsignedByte(A, AOff, len) + getUnsignedByte(B, BOff, len) + result);
            // store the result in byte array C
            C[(byte) (len + COff)] = (byte) result;
            // has a carry?
            if (result > 0x00FF) {
                result = 1;
                result = (short) (result + 0x100);
            } else {
                result = 0;
            }
        }
        //produce overflow in the sum.
        if (result == 1) {
            return false;
        }
        return true;
    }
   
   private static short getUnsignedByte(byte[] A, byte AOff, byte count) {
       return (short) (A[(short) (count + AOff)] & 0x00FF);
   }

   
}
