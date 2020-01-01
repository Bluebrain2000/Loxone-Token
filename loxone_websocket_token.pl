#!/usr/bin/perl
print "Content-type: text/javascript\n\n";

# Ausgabe von JavaScript Code
# token_valid, keyexchange_command und token_auth_command
# in JavaScript:
# token_valid auf == 1 prüfen
# wenn 1, dann den Websocket öffnen und keyexchange_command senden
# wenn erfolgreich (code 200), dann noch token_auth_command senden

$miniserver_ip = "192.168.0.21";
$user = 'alexa';
$password = '********';
$permission = 4;
$uuid = "aaaaaaaa-bbbb-cccc-dddddddddddddd01";
$info = "TVserver";

print "user='$user';\n";

use LWP::Simple;			# einfacher web crawler
use JSON::Parse qw(parse_json valid_json);	# JSON parser, es werden nur die Funktionen zum parsen und validieren von JSON benötigt
use Digest::SHA1  qw(sha1_hex);
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);
use MIME::Base64;			# Base64 en/decoder
use Crypt::Mode::CBC;		# universelles Crypto-Modul, wir verwenden aber nur AES
use Crypt::PK::RSA;			# RSA Crypto-Modul
use URI::Escape;			# Modul zum URI/URL escapen

# Key und Salt vom user vom Miniserver holen
$content = get("http://$miniserver_ip/jdev/sys/getkey2/$user");
# JSON response parsen
$json = parse_json($content);
# key und salt aus der JSON response in Variablen speichern
$key_hex = $json->{LL}->{value}->{key};
$salt_hex = $json->{LL}->{value}->{salt};

$key_bin = pack('H*',$key_hex);		# HEX-String in BIN-String umwandeln
$salt_bin = pack('H*',$salt_hex);	# HEX-String in BIN-String umwandeln

# Erstellen vom ersten Hash, der zu bilden ist aus dem Benutzerpasswort und dem zuvor abgerufenen Salt:
$password_salt=$password.":".$salt_hex;	# /!\ Salt in HEX Form!!!
# SHA1 Hash erzeugen.
# /!\ Mit uc() muss der Hash noch in Uppercase konvertiert werden, sonst funktioniert es nicht!
$pwHash = uc(sha1_hex($password_salt));

# HMAC SHA1 aus Benutzername und dem zuvor erzeugten SHA1 Hash mit dem anfangs abgerufenen Key erzeugen:
# /!\ Anders als der Salt, muss der Key hier in Binary Form verwendet werden!
$data=$user.":".$pwHash;
$hash = hmac_sha1_hex($data, $key_bin);

# Kommando vorbereiten
# $hash der zuletzt erzeugt wurde
# $user Benutzername, sowie $permission, $uuid und $info wie anfangs definiert
$cmd="jdev/sys/gettoken/$hash/$user/$permission/$uuid/$info";
#$cmd="jdev/sys/getjwt/$hash/$user/$permission/$uuid/$info";

# Public Key vom Miniserver holen:
$content = get("http://$miniserver_ip/jdev/sys/getPublicKey");
# JSON response parsen:
$json = parse_json($content);
# Public Key aus dem JSON in $publicKey_content speichern:
$publicKey_content = $json->{LL}->{value};
# Loxone gibt den Key fälschlicherweise als Zertifikat aus, also schreiben wir das mit RegEx um:
$publicKey_content=~s/-----BEGIN CERTIFICATE-----/-----BEGIN PUBLIC KEY-----/;
$publicKey_content=~s/-----END CERTIFICATE-----/-----END PUBLIC KEY-----/;

# beliebiger Salt, 2 Bytes
$salt2="1122";
# und zuvor erzeugtes Kommando anhängen
$plaintext = "salt/$salt2/".$cmd;

# beliebiger AES-256 cbc Key (32 Byte) und Initialisierungsvektor (16 Byte):
$AESkey_hex = "4141414141414141414141414141414141414141414141414141414141414141";
$AESiv_hex =  "42424242424242424242424242424242";
# beides noch ins Binärformat umwandeln:
$AESkey = pack('H*', $AESkey_hex);
$AESiv = pack('H*', $AESiv_hex);

# $plaintext mit dem gerade erstellen AES Key und iv verschlüsseln
# /!\ WICHTIG! zero-padding verwenden!!!
$cbc = Crypt::Mode::CBC->new('AES',4);	# 4: padding=zero-padding
$cipher_bin = $cbc->encrypt($plaintext, $AESkey, $AESiv);
# und den Cipher noch in Base63 encodieren
$cipher_base64 = encode_base64($cipher_bin,'');
# sowie URI escapen damit keine reservierten Zeichen (+ = / etc.) in der URL vorkommen
$cipher_base64_uri_encoded = uri_escape($cipher_base64);

# eigentlichen Aufruf vorbereiten
# bei /enc/ antwortet der Miniserver unverschlüsselt, bei /fenc/ verschlüsselt
$cmd = "jdev/sys/enc/".$cipher_base64_uri_encoded;

# der eigene AES key und iv müssen dem Miniserver noch mitgegeben werden mit dem Aufruf
# verschlüsselt werden diese mit RSA und dem Public Key vom Miniserver
# /!\ RSA Parameter: ECB, PKCS1, Base64 with NoWrap

# payload mit AES key und iv erstellen:
$payload = $AESkey.":".$AESiv;

# Public Key mit Referenz auf die Variable einlesen
$pub = Crypt::PK::RSA->new(\$publicKey_content);
# verschlüsseln
# /!\ WICHTIG: der 2. Parameter, 'v1.5' sagt dem Modul, dass PKCS1 Padding verwendet werden soll statt dem default oaep Padding
$session_key = $pub->encrypt($payload, 'v1.5');
# Base64 encodieren
$session_key_base64 = encode_base64($session_key,'');
# und noch URI escapen
$enc_session_key_base64 = uri_escape($session_key_base64);

print "keyexchange_command='jdev/sys/keyexchange/$session_key_base64';\n";

# vollständige URL basteln
# Der String mit dem RSA verschlüsselten AES key und iv wird am Ende als Parameter ?sk= angehängt
$url="http://$miniserver_ip/".$cmd."?sk=".$enc_session_key_base64;

# Zum Miniserver schicken und die Ausgabe anzeigen.
$content = get($url);
# Wenn alles richtig gelaufen ist, dann sollte das jetzt die JSON Response mit dem Token sein
# z.B. {"LL":{"control":"dev/sys/gettoken/6d5478a6ad9b9c0c8d2c3287452c8880f1f8c6c3/alexa/4/aaaaaaaa-bbbb-cccc-dddddddddddddd01/TVserver","value":{"token":"A12D33BBE29EE34CCCD070E01CEAB94A2D9FBA09","key":"45344331344435393432334646433430463345303542393944313745353637413433444239394634","validUntil":351877773,"tokenRights":1668,"unsecurePass":false},"code":"200"}}

# der Vollständigkeit halber:
# JSON Response auf Gültigkeit prüfen
if(valid_json($content)) {
	# JSON Response parsen
	$json = parse_json($content);
	# Token und Ablaufdatum auslesen
	$token = $json->{LL}->{value}->{token};
	if($token) {
		print "token_valid=1;\n";
		
		$validUntil = $json->{LL}->{value}->{validUntil} + 1230764400; # 1230764400 addieren, weil der miniserver ab 01.01.2009 rechnet statt 01.01.1970
		print "token_validUntil=$validUntil;\n";
		
		$key_hex = $json->{LL}->{value}->{key};
		$key_bin = pack('H*',$key_hex);
		$hash = hmac_sha1_hex($token, $key_bin);
		
		# authwithtoken
		$authCmd="authwithtoken/$hash/$user";
		$cipher="salt/$salt2/$authCmd";
			# /!\ WICHTIG! zero-padding verwenden!!!
			$cbc = Crypt::Mode::CBC->new('AES',4);	# 4: padding=zero-padding
			$cipher_bin = $cbc->encrypt($cipher, $AESkey, $AESiv);
			# und den Cipher noch in Base63 encodieren
			$cipher_base64 = encode_base64($cipher_bin,'');
			# sowie URI escapen damit keine reservierten Zeichen (+ = / etc.) in der URL vorkommen
			$cipher_base64_uri_encoded = uri_escape($cipher_base64);
		$encrypted_command="jdev/sys/enc/$cipher_base64_uri_encoded";
		print "token_auth_command='$encrypted_command';\n";
	} else {
		print "token_valid=0;\n";
	}
} else {
	print "token_valid=0;\n";
}











