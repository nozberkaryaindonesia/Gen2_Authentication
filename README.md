#Gen2 Authentication between a WISP Tag and a USRP Reader#

##Summary##
This git contains the source codes to present the demo named "Gen2 Authentication between a WISP Tag and a USRP Reader" as well as to further develop software tools for the interaction WISP tags and USRP readers. The codes for the USRP reader is based upon Michael Buettner's "Gen 2 RFID Tools" (fork from: https://www.cgran.org/wiki/Gen2), while the codes for the WISP tag is based upon the standard firmware provided by the WISP community (fork from: http://wisp.wikispaces.com/WISPFirmware).

This demo essentially confirms that authentication (based on symmetric cryptographic primitives) is able to be performed under the current framework specified by the EPC Gen2 standard.

##Demo##
A video record of this demo can be found here: xxxxxxxxxx


##Hardware Setup##
1. USRP1 from ettus (the black one)
2. Two RFX900 daughterboards, properly plugged to the USRP1
3. Two antennas attach to TX/RX ports on the two daughterboards respectively: (1) onnect the standard dipole antenna (https://www.ettus.com/product/details/VERT900) to daughterboard A; (2) connect the mini-guardrail antenna (http://www.impinj.com/Documents/Reader_Antennas/Mini-Guardrail_Antenna_Datasheet) to daughterboard B
4. Connect the WISP tag to the USB debugger, where the latter is connected to computer running Windows XP
5. Load the (tweaked) WISP firmware to the WISP tag (the blue one 0x41) via IAR Embedded Workbench for TI MSP430 v5.40 (downloaded from http://www.iar.com/en/Products/IAR-Embedded-Workbench/TI-MSP430/)
6. Let the tag stand CLOSELY in the middle of the mini-guardrail antenna. Make sure the tag faces the antenna.


##Install GnuRadio and Gen 2 RFID Tools Manually##
1. install Ubuntu 10.04(lucid) 32-bit LTS. (while 64-bit version should also work)
2. download/install necessary linux tools:

	sudo apt-get install git-core; sudo apt-get install subversion
	sudo apt-get -y install libfontconfig1-dev libxrender-dev libpulse-dev \
	swig g++ automake autoconf libtool python-dev libfftw3-dev \
	libcppunit-dev libboost-all-dev libusb-dev fort77 sdcc sdcc-libraries \
	libsdl1.2-dev python-wxgtk2.8 git-core guile-1.8-dev \
	libqt4-dev python-numpy ccache python-opengl libgsl0-dev \
	python-cheetah python-lxml doxygen qt4-dev-tools \
	libqwt5-qt4-dev libqwtplot3d-qt4-dev pyqt4-dev-tools python-qwt5-qt4 git-core

3. download GnuRadio and Gen 2 RFID Tools:

	git clone http://gnuradio.org/git/gnuradio.git

4. copy ~/gen2_rfid/trunk/rfid/misc_files/usrp_source_base.cc to ~/gnuradio/gr-usrp/src/ (please find "gen2_rfid" folder in the EnvClone and copy it to ~) and copy ~/gen2_rfid/trunk/rfid/misc_files/fusb_linux.cc to ~/gnuradio/usrp/host/lib/

5. Install GnuRadio (following the instructions in http://gnuradio.org/redmine/projects/gnuradio/wiki/UbuntuInstall)

	cd gnuradio
	git reset --hard 26fc07eac6a3029e2d7361b1502f69e7592e708b
	./bootstrap
	./configure
	make
	make check
	sudo make install

6. Configuring USRP support (when USRP1 is connected to the computer via USB cable)

	sudo addgroup usrp
	sudo usermod -G usrp -a <YOUR_USERNAME>
	echo 'ACTION=="add", BUS=="usb", SYSFS{idVendor}=="fffe", SYSFS{idProduct}=="0002", GROUP:="usrp", MODE:="0660"' > tmpfile
	sudo chown root.root tmpfile
	sudo mv tmpfile /etc/udev/rules.d/10-usrp.rules
	sudo killall -HUP udevd
	ls -lR /dev/bus/usb | grep usrp

if something meaningful is displayed, the USRP is now works with the system

7. Install Gen 2 RFID Tools (follow the instructions in https://www.cgran.org/browser/projects/gen2_rfid/trunk/rfid/README.rfid)

	cd gen2_rfid/trunk/rfid/
	./bootstrap; ./configure; make; sudo make install;
	sudo ldconfig

5. To run the demo, by assuming the hardware is connected properly, open a command/terminal window

	cd gen2_rfid/trunk/rfid/apps/
	sudo GR_SCHEDULER=STS nice -n -20 ./WISP_reader.py


##How the Authentication Works##
In EPC C1G2 standard, the QUERY carries out in the following fashion:
	Reader				               				Tag
				-----------QUERY---------->
				<----------RN16------------
				----------ACK(RN16)------->
				<-----------EPC------------
				------------NAK----------->

Due to the stringent responding timing as required by EPC C1G2, I have to use two QUERY sessions to complete one authentication (since the computation of the authentication code, even with the lightweight stream cipher WG-7 (http://goo.gl/siUm8), takes sooooo long). My design of the interactions for the authentication purpose can be described as follows:
	Reader											Tag
				-----------QUERY---------->
				<----------RN16_T----------
				--------ACK(RN16_R)------->
													Compute the authentication code
				-----------QUERY---------->
				<----------RN16_T----------
				---------ACK(0001)-------->
				<-------EPC(AUTH CODE)-----
				------------NAK----------->
	verify

To summarize:
1. The reader sends out QUERY command to wake up a tag.
2. The tag responses with a 16-bit random number (denote it as RN16_T), reading from its temperature sensor. So, an interesting thing is that touching the WISP tag helps to generate more random-looking numbers.
3. Next, ACK command is sent from the reader to the tag, where the payload is another 16-bit random number (denote it as RN16_R).
4. The tag starts to compute the authentication code, i.e., E(RN16_R||RN16_T, K), where K is the secret key shared between the reader and the tag and E is the WG-7 stream cipher (the newer version with 13 tap positions). This takes quite a while.
5. The reader sends another QUERY after a short break. 
6. If the tag finishes the computation of the authentication code, it responses the same RN16_T. (Otherwise, it gives no response and the reader will repeat step 5).
7. The reader then sends out another ACK command with a special payload "0001" to inform the tag to send back the authentication code produced.
8. The tag sends back the 96-bit authentication code.
9. The reader clears up the session by sending NAK command and checks if the received authentication code is valid. If so, the tag authenticates itself to the reader.
10. Note that both RN16_T and RN16_R are too short to be used in a real authentication scenario. I did in this way primarily because it is a demo and random number generation is not easy with the current WISP tag.


##Misc##

###EPC C1G2 standard###
EPC C1G2 standard is especially useful for this demo (especially page 88, 89, 90, 97), which can be accssed from here: http://www.gs1.org/gsmp/kc/epcglobal/uhfc1g2/uhfc1g2_1_2_0-standard-20080511.pdf.

###How to hack Gen 2 RFID Tools to make it work (for my purpose)###
Michael's implementation is awesome. However, due to the use of different antennas, the gen2 reader does not produce meaningful results for me at the very beginning. Hence, following tweaks are applied:
1. Decoding: I used a more aggressive decoding method for pulling out tag's message bits from the sampled signals (see rfid_tag_decoder_f.cc for details). It does not mean to be generally superior, but it does work well in this implementation.
2. Timing: as aforementioned, two Gen2 QUERY sessions are used to accomplish one authentication session.
