#!/usr/bin/perl
use CGI::Carp qw(fatalsToBrowser);	# Fehlermeldungen an den Browser ausgeben (sonst nur in der Konsole sichtbar)
print "Content-type: text/plain\n\n";	# für die Ausgabe im Browser, nur plain text, keine Lust auf HTML Formatierung 

# Crashkurs in Perl damit das Lesen vom Code ggf. einfacher fällt :)
# Punkt (".") verbindet strings
# Variablen (Skalare) beginnen mit einem $ Zeichen, z.B. $name="Alexa"; (Arrays beginnen mit @ und Hashes mit %)
# "use XXX::YYYY" lädt ein Modul

# IP Adresse vom Miniserver sowie Benutzername und Passwort vom zu verwendenden User
$miniserver_ip = "192.168.0.21";
$user = 'alexa';
$password = '********';
$permission = 4;				# 4=App (Token ist mehrere Wochen gültig) siehe schrottige Loxone API Doku
$uuid = "aaaaaaaa-bbbb-cccc-dddddddddddddd01";	# beliebige ID mit der sich die Anwendung beim Miniserver identifiziert.
$info = "TVserver";				# beliebiger Name von der App o.ä.

# notwendige Module laden
# (werden am Server z.B. mit "cpan -i URI::Escape" installiert)
use LWP::Simple;			# einfacher web crawler
use JSON::Parse qw(parse_json valid_json);	# JSON parser, es werden nur die Funktionen zum parsen und validieren von JSON benötigt
use Digest::SHA1  qw(sha1_hex);
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);
use MIME::Base64;			# Base64 en/decoder
use Crypt::Mode::CBC;			# universelles Crypto-Modul, wir verwenden aber nur AES
use Crypt::PK::RSA;			# RSA Crypto-Modul
use URI::Escape;			# Modul zum URI/URL escapen

# Key und Salt vom user vom Miniserver holen
$content = get("http://$miniserver_ip/jdev/sys/getkey2/$user");
# JSON response parsen
$json = parse_json($content);
# key und salt aus der JSON response in Variablen speichern
$key_hex = $json->{LL}->{value}->{key};
$salt_hex = $json->{LL}->{value}->{salt};

# Anzeige vom Key in HEX und BIN/String Form (enthält nur alphanumerische Zeichen)
print "key_hex: $key_hex\n";
$key_bin = pack('H*',$key_hex);		# HEX-String in BIN-String umwandeln
print "key_bin: $key_bin\n";
# das gleiche mit dem Salt
print "salt_hex: $salt_hex\n";
$salt_bin = pack('H*',$salt_hex);	# HEX-String in BIN-String umwandeln
print "salt_bin: $salt_bin\n";

print "\n";	# Zeilenumbruch zwecks Übersichtlichkeit

# Erstellen vom ersten Hash, der zu bilden ist aus dem Benutzerpasswort und dem zuvor abgerufenen Salt:
$password_salt=$password.":".$salt_hex;	# /!\ Salt in HEX Form!!!
print "password:salt $password_salt\n";
# SHA1 Hash erzeugen.
# /!\ Mit uc() muss der Hash noch in Uppercase konvertiert werden, sonst funktioniert es nicht!
$pwHash = uc(sha1_hex($password_salt));
print "pwHash: $pwHash\n";

# HMAC SHA1 aus Benutzername und dem zuvor erzeugten SHA1 Hash mit dem anfangs abgerufenen Key erzeugen:
# /!\ Anders als der Salt, muss der Key hier in Binary Form verwendet werden!
$data=$user.":".$pwHash;
print "user_pwHash: $data\n";
$hash = hmac_sha1_hex($data, $key_bin);
print "hash: $hash\n";

print "\n";

# Kommando vorbereiten
# $hash der zuletzt erzeugt wurde
# $user Benutzername, sowie $permission, $uuid und $info wie anfangs definiert
$cmd="jdev/sys/gettoken/$hash/$user/$permission/$uuid/$info";
print "cmd: $cmd\n";

print "\n";

# Public Key vom Miniserver holen:
$content = get("http://$miniserver_ip/jdev/sys/getPublicKey");
# JSON response parsen:
$json = parse_json($content);
# Public Key aus dem JSON in $publicKey_content speichern:
$publicKey_content = $json->{LL}->{value};
print "publicKey_content: $publicKey_content\n";
# Loxone gibt den Key fälschlicherweise als Zertifikat aus, also schreiben wir das mit RegEx um:
$publicKey_content=~s/-----BEGIN CERTIFICATE-----/-----BEGIN PUBLIC KEY-----/;
$publicKey_content=~s/-----END CERTIFICATE-----/-----END PUBLIC KEY-----/;
print "publicKey_content: $publicKey_content\n";

print "\n";

# beliebiger Salt, 2 Bytes
$salt2="1122";
# und zuvor erzeugtes Kommando anhängen
$plaintext = "salt/$salt2/".$cmd;
print "plaintext: $plaintext\n";

print "\n";

# beliebiger AES-256 cbc Key (32 Byte) und Initialisierungsvektor (16 Byte):
$AESkey_hex = "4141414141414141414141414141414141414141414141414141414141414141";
$AESiv_hex =  "42424242424242424242424242424242";
print "AESkey_hex: $AESkey_hex\n";
print "AESiv_hex: $AESiv_hex\n";
# beides noch ins Binärformat umwandeln:
$AESkey = pack('H*', $AESkey_hex);
$AESiv = pack('H*', $AESiv_hex);

# $plaintext mit dem gerade erstellen AES Key und iv verschlüsseln
# /!\ WICHTIG! zero-padding verwenden!!!
$cbc = Crypt::Mode::CBC->new('AES',4);	# 4: padding=zero-padding
$cipher_bin = $cbc->encrypt($plaintext, $AESkey, $AESiv);
# und den Cipher noch in Base63 encodieren
$cipher_base64 = encode_base64($cipher_bin,'');
print "ciphertext_base64: $cipher\n";
# sowie URI escapen damit keine reservierten Zeichen (+ = / etc.) in der URL vorkommen
$cipher_base64_uri_encoded = uri_escape($cipher_base64);
print "cipher_uri_encoded: $cipher_base64_uri_encoded\n";

print "\n";

# eigentlichen Aufruf vorbereiten
# bei /enc/ antwortet der Miniserver unverschlüsselt, bei /fenc/ verschlüsselt
$cmd = "jdev/sys/enc/".$cipher_base64_uri_encoded;
print "cmd: $cmd\n";

print "\n";

# der eigene AES key und iv müssen dem Miniserver noch mitgegeben werden mit dem Aufruf
# verschlüsselt werden diese mit RSA und dem Public Key vom Miniserver
# /!\ RSA Parameter: ECB, PKCS1, Base64 with NoWrap

# payload mit AES key und iv erstellen:
$payload = $AESkey.":".$AESiv;
print "payload: $payload\n";

# Public Key mit Referenz auf die Variable einlesen
$pub = Crypt::PK::RSA->new(\$publicKey_content);
# verschlüsseln
# /!\ WICHTIG: der 2. Parameter, 'v1.5' sagt dem Modul, dass PKCS1 Padding verwendet werden soll statt dem default oaep Padding
$session_key = $pub->encrypt($payload, 'v1.5');
# Base64 encodieren
$session_key_base64 = encode_base64($session_key,'');	# der 2. Parameter '' sorgt dafür, dass kein Zeilenumbruch gemacht wird, sonst Standard nach 76 Zeichen
print "session_key_base64: $session_key_base64\n";
# und noch URI escapen
$enc_session_key_base64 = uri_escape($session_key_base64);
print "enc_session_key_base64: $enc_session_key_base64\n";

print "\n";

# vollständige URL basteln
# Der String mit dem RSA verschlüsselten AES key und iv wird am Ende als Parameter ?sk= angehängt
$url="http://$miniserver_ip/".$cmd."?sk=".$enc_session_key_base64;
print "url: $url\n";

print "\n";

# Zum Miniserver schicken und die Ausgabe anzeigen.
$content = get($url);
# Wenn alles richtig gelaufen ist, dann sollte das jetzt die JSON Response mit dem Token sein
# z.B. {"LL":{"control":"dev/sys/gettoken/6d5478a6ad9b9c0c8d2c3287452c8880f1f8c6c3/alexa/4/aaaaaaaa-bbbb-cccc-dddddddddddddd01/TVserver","value":{"token":"A12D33BBE29EE34CCCD070E01CEAB94A2D9FBA09","key":"45344331344435393432334646433430463345303542393944313745353637413433444239394634","validUntil":351877773,"tokenRights":1668,"unsecurePass":false},"code":"200"}}
print $content;

print "\n\n";

# der Vollständigkeit halber:
# JSON Response auf Gültigkeit prüfen
if(valid_json($content)) {
	# JSON Response parsen
	$json = parse_json($content);
	# Token und Ablaufdatum auslesen
	$token = $json->{LL}->{value}->{token};
	$validUntil = $json->{LL}->{value}->{validUntil} + 1230764400; # 1230764400 addieren, weil der miniserver ab 01.01.2009 rechnet statt 01.01.1970
	# Fleißaufgabe: Datum und Uhrzeit aus Unixtime berechnen (Funktion siehe am Ende)
	&date($validUntil);
	print "Token: $token\n";
	print "validUntil: $validUntil ($CCyear-$CCmon-$CCmday $CChour:$CCmin:$CCsec)\n";
} else {
	print "ERROR: no valid JSON";
}

# Datum und Uhrzeit aus Unixtime berechnen
sub date {
    local ($CCtime) = @_;
    ($CCsec,$CCmin,$CChour,$CCmday,$CCmon,$CCyear,$CCwday) = (localtime($CCtime))[0,1,2,3,4,5,6];
	$CCmonname=$Months[$CCmon];
    if ($CCsec < 10) { $CCsec = "0$CCsec"; }
    if ($CCmin < 10) { $CCmin = "0$CCmin"; }
    if ($CChour < 10) { $CChour = "0$CChour"; }
    if ($CCmday < 10) { $CCmday = "0$CCmday"; }
    $CCmon++;
    if ($CCmon < 10) { $CCmon = "0$CCmon"; }
	if ($CCyear < 50) { $CCyear += 100; }
    $CCyear = $CCyear+1900;
}
