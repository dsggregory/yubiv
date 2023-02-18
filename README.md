# Yubikey Resources

## OTP (One Time Password)
Terminology:
* YubiKey - the hardware device itself
* YubiKey Token - the string that the YubiKey writes when pressed
* YubiKey ID - the first 12 characters of every token used to identify the device

A Yubikey [OTP](https://developers.yubico.com/OTP/OTPs_Explained.html) is generated when you press the yubikey. It creates a 44-byte string where the first 12 bytes indicate the unique ID assigned to the yubikey followed by an AES-128 encrypted key.
<table>
<tr>
<td colspan=2>YubiKey Token</td>
</tr>
<tr>
<td colspan=2><u>ccccccjddvfl</u><i>ilccvdehcjgjttvjchrrddvijcfvvnkl</i></td>
</tr>
<tr>
<td><b>Yubikey ID</b></td>
<td><b>Unique Passcode + Counter (OTP) </b></td>
</tr>
<tr>
<td>ccccccjddvfl</td>
<td>ilccvdehcjgjttvjchrrddvijcfvvnkl</td>
</tr>
</table>

> Each YubiKey has two slots. The first slot is used to generate the passcode when the YubiKey is touched for between 0.3 and 1.5 seconds and released. The second slot is used if the button is touched between 2 and 5 seconds. When the YubiKey is shipped its first configuration slot is factory programmed for the "Works with YubiKey" YubiCloud OTP service and the second configuration slot is blank.

### Yubico Validation
Out of the box, a Yubikey is able to be validated using the Yubico servers and their API.

### Self-Hosted Validation
Validating One-Time-Passwords (OTP) requires knowledge of a map of Yubikey ID to Secret AES Key.

I used `Yubikey Manager` to configure the long press slot 2 so I could get the Secret AES key. Write these down when creating as you won't be able to get them later. Leave slot 1 alone (and validate to this service with a long press). Slot 1 is then still configured for the Yubi cloud server verification likely needed by apps you've already configured it for use (e.g. VPN client). 

Steps to perform this after downloading and running the Yubikey Manager are as follows:
* Select Applications/OTP
* Press Configure for slot 2
* Tick the `use serial` for the public key
* Press generate for the other boxes
* __COPY__ down all values presented and store in a safe place
* Complete the wizard

You will then use the copied values when registering your Yubikey with cluster-terminal.

## References
* https://duo.com/docs/yubikey
* https://github.com/stumpyfr/yubikey-server
* https://github.com/dgryski/go-yubicloud/blob/master/ycloud.go
* https://github.com/conformal/yubikey
* https://github.com/GeertJohan/yubigo
* https://github.com/Yubico/yubico-c - to generate test tokens