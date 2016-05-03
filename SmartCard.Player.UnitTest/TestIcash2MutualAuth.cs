using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
//
using Spring.Context;
using Spring.Context.Support;
using Common.Logging;
//
using NUnit.Framework;
//
using SmartCard.Pcsc;
using SmartCard.Player;
using Kms2.Crypto.Common;

namespace SmartCard.Player.UnitTest
{
    [TestFixture]
    public class TestIcash2MutualAuth
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestIcash2MutualAuth));
        //
        private bool chkOK = false;
        private IApplicationContext ctx;
        private IKeyDeriver keyDeriver;
        private IHexConverter hexConverter;
        private IByteWorker byteWorker;
        private IRandWorker randWorker;
        //
        private ICard cardNative;
        private APDUPlayer icash2Player = null;
        //
        private ISymCryptor symCryptor = null;
        private ICMacWorker cMacWorker = null;
        private ICrcWorker<uint> nxpCrc32Worker = null;
        //
        private byte[] uid = null;
        private byte[] divKey = null;

        private string seedKeyMasterHex = "DCA15D2F402E1C14F069C80FAAA1002F";
        private string seedKey0Hex = "DA86D23592B1CAB3740B298D2C8E5CC3";
        private string seedKeyAHex = "FDA01F10E42489733FE1EE514AC55E92";
        private string seedKeyBHex = "EEEA4C617D2880C83BC2358AF645EBDC";
        private string seedKeyCHex = "082CBB7C855C366CCFBF4A07444BA989";
        //private string seedKey1Hex =
        private string seedKey2Hex = "A40A37803FEA38852FEA19FB372538F3";

        //private string origMasterKeyHex = "0000000000000000"
        //                                + "0000000000000000";
        //

        private ISymCryptor tDesCryptor = null;

        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.keyDeriver = ctx["aes128KeyDeriver"] as IKeyDeriver;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.icash2Player = ctx["apduPlayer"] as APDUPlayer;
            this.randWorker = ctx["randWorker"] as IRandWorker;
            this.cMacWorker = ctx["aes128CMacWorker"] as ICMacWorker;
            this.nxpCrc32Worker = ctx["nxpCrc32Worker"] as ICrcWorker<uint>;
            this.tDesCryptor = ctx["tripleDesCbcCryptor"] as ISymCryptor;
            //            
            //
            this.cardNative = this.icash2Player.CardNative;
            //
            this.icash2Player.LoadCommandFile("Icash2CmdList.xml");
            //
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            // find first MifareDesfire EV1 card
            foreach (string reader in readers)
            {
                try
                {
                    log.Debug("Connect: [" + reader + "]....");
                    this.cardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                    byte[] atrValue = this.cardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    string atrHex = this.hexConverter.Bytes2Hex(atrValue);
                    //
                    log.Debug("ATR:[" + atrHex + "]");
                    // MifareDesfire EV1 card
                    if
                    (
                        "3B8180018080".Equals(atrHex)
                     || "3B8A80010031C173C8400000900090".Equals(atrHex)
                     || "3B8E800180318066B1C5230100ED83009000F0".Equals(atrHex)
                     || "3B8F8001804F0CA000000306030001000000006A".Equals(atrHex)
                    )
                    {
                        log.Debug("Got MifareDesfire EV1 card in [" + reader + "]");
                        APDUResponse response = this.icash2Player.ProcessSequence("GetUID");
                        this.uid = response.Data;
                        string uidHex = this.hexConverter.Bytes2Hex(this.uid);
                        log.Debug("Got icash2 uid:[" + uidHex + "]");
                        chkOK = true;
                        break;
                    }
                    else
                    {
                        this.cardNative.Disconnect(DISCONNECT.Unpower);
                        log.Debug("reader:" + reader + " card unknow!");
                    }
                } catch (Exception ex)
                {
                    log.Debug(ex.Message);
                }
            }
            if( !chkOK )
            {
                log.Debug("No match card exists!");
                return;
            }
        }


        //[Test]
        //public void Test01AuthOrigMaster()
        //{               
        //    SequenceParameter sp = new SequenceParameter();
        //    APDUResponse response = null;
        //    //
        //    log.Debug("Get PICC Master Key Setting...");
        //    response = this.icash2Player.ProcessSequence("SelectPICC");
        //    log.Debug(response);
        //    response = this.icash2Player.ProcessSequence("GetKeySettings");
        //    log.Debug(response);
        //    if (response.SW1 == 0x91 && response.SW2 == 0x00)
        //    {
        //        log.Debug("data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
        //    }
        //    //
        //    // 2key, 3Des
        //    log.Debug("Authenticate(3)DES with PICC Master Key ...");
        //    sp.Clear();
        //    sp.Add("AID", "000000");
        //    sp.Add("KN", "00" );
        //    response = this.icash2Player.ProcessSequence("Authenticate(3)DES", sp );
        //    log.Debug(response);
        //    if (response.SW1 == 0x91 && response.SW2 == 0x00)
        //    {
        //        log.Debug("data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
        //    }
        //    byte[] encRndB = response.Data;
        //    byte[] iv = this.byteWorker.Fill(8, 0x00);
        //    this.tDesCryptor.SetIv( iv );
        //    byte[] kx = this.byteWorker.Fill( 16, 0x00);                
        //    this.tDesCryptor.SetKey(kx);
        //    //
        //    byte[] rndB = this.tDesCryptor.Decrypt(encRndB);
        //    log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
        //    // get next iv
        //    //iv = this.byteWorker.SubArray( response.Data, response.Data.Length - 8, 8);
        //    log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
        //    // PCD Gen rndA
        //    byte[] rndA = this.randWorker.GetBytes(8);
        //    log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
        //    //
        //    byte[] rndARndBROL8 = this.byteWorker.Combine
        //    (
        //        rndA
        //      , this.byteWorker.RotateLeft(rndB, 1)
        //    );
        //    log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
        //    //this.tDesCryptor.SetIv(iv);
        //    byte[] encRndARndBROL8 = this.tDesCryptor.Encrypt(rndARndBROL8);
        //    log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
        //    // get next iv 
        //    //iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 8, 8);
        //    log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
        //    //
        //    sp.Add("LEN", "10"); // 0x10
        //    sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
        //    response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
        //    log.Debug(response);
        //    byte[] encRndAROL8 = response.Data;
        //    if (response.SW1 == 0x91 && response.SW2 == 0x00)
        //    {
        //        log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
        //    }
        //    //
        //    //this.tDesCryptor.SetIv(iv);
        //    byte[] rndAROL8 = this.tDesCryptor.Decrypt(encRndAROL8);            
            
        //    log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(rndAROL8) + "]");
        //    Assert.AreEqual(this.byteWorker.RotateRight(rndAROL8, 1), rndA);
        //}

        //[Test]
        //public void Test03GetKeySettings()
        //{
        //    log.Debug("Get PICC Master Key Settings...");
        //    SequenceParameter sp = new SequenceParameter();
        //    APDUResponse response = null;
        //    //
        //    response = this.icash2Player.ProcessSequence("SelectPICC");
        //    log.Debug(response);
        //    response = this.icash2Player.ProcessSequence("GetKeySettings");
        //    log.Debug(response);
        //    if (response.SW1 == 0x91 && response.SW2 == 0x00)
        //    {
        //        log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
        //    }
        //    //
        //    log.Debug("Get AID 118716 Master Key Settings...");
        //    sp.Clear();
        //    sp.Add("AID", "118716");
        //    response = this.icash2Player.ProcessSequence("SelectAID", sp);
        //    log.Debug(response);
        //    //
        //    byte[] sesKey = this.doAuth("0");
        //    log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
        //    //            
        //    response = this.icash2Player.ProcessSequence("GetKeySettings");
        //    log.Debug(response);
        //    if (response.SW1 == 0x91 && response.SW2 == 0x00)
        //    {
        //        log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
        //    }
        //    // update iv
        //    this.cMacWorker.SetMacKey(sesKey);
        //    this.cMacWorker.SetIv(SymCryptor.ConstZero);
        //    byte[] ivData = this.hexConverter.Hex2Bytes("45");
        //    this.cMacWorker.DataInput(ivData);
        //    byte[] iv = this.cMacWorker.GetMac();
        //    log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
        //    // check if cmac ok
        //    //   update iv
        //    this.cMacWorker.SetIv(iv);    
        //    // data || status
        //    byte[] macData = 
        //        this.byteWorker.Combine
        //        (
        //            this.byteWorker.SubArray( response.Data,0, 2)
        //           ,new byte[] { response.SW2 }
        //        );
        //    this.cMacWorker.DataInput(macData);
        //    iv = this.cMacWorker.GetMac();
        //    // get first 8 bytes of iv
        //    log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
        //    byte[] cmac = byteWorker.SubArray(iv, 0, 8);
        //    log.Debug("cmac:[" + this.hexConverter.Bytes2Hex(cmac) + "]" );
        //    Assert.AreEqual(this.byteWorker.SubArray(response.Data, 2, 8), cmac);                       
        //    //
        //    APDULog[] arrayLog = this.icash2Player.Log.ToArray();
        //    for (int nI = 0; nI < arrayLog.Length; nI++)
        //        log.Debug(arrayLog[nI].ToString());
        //}

        [Test]
        public void TestReadManuDate()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] sesKey = this.doAuth("A");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            SequenceParameter sp = new SequenceParameter();
            log.Debug("Read FNO 01...");
            sp.Clear();
            sp.Add("FD", "01000000040000");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("BD" + "01000000040000");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            log.Debug("Card Manufacture Date:[" + this.hexConverter.Bytes2Hex(readData) + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                // decrypted data
                    readData
                // status
                  , new byte[] { response.SW2 }
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex( BitConverter.GetBytes(crcResult) ) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void TestReadCardFormatMember()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] sesKey = this.doAuth("A");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            SequenceParameter sp = new SequenceParameter();
            log.Debug("Read FNO 02...");
            sp.Clear();
            sp.Add("FD", "02070000080000");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("BD" + "02070000080000");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 8);
            log.Debug("CardFormatMember:[" + this.hexConverter.Bytes2Hex(readData) + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 8, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                // decrypted data
                    readData
                // status
                  , new byte[] { response.SW2 }
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void TestReadFormatVersion()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] sesKey = this.doAuth("A");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            SequenceParameter sp = new SequenceParameter();
            log.Debug("Read FNO 02...");
            sp.Clear();
            sp.Add("FD", "02050000020000");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("BD" + "02050000020000");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 2);
            log.Debug("FormatVersion:[" + this.hexConverter.Bytes2Hex(readData) + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 2, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                // decrypted data
                    readData
                // status
                  , new byte[] { response.SW2 }
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void Test06SetCardStatus()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            SequenceParameter sp = new SequenceParameter();
            byte[] iv = null;           
            byte[] sesKey = this.doAuth("B");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("WriteData with FNO 05...");
            byte[] rawData = new byte[] { 0x01 };
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                ( 
                    "3D" + "05" + "080000" + "010000" 
                )
               ,rawData  // cmd(1) || fileNo(1) || offset(3) || length(3) || rawData(1)
            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            //
            byte[] decryptedMsg = this.byteWorker.ZeroPadding
            (
                this.byteWorker.Combine
                (
                    rawData  // (1)
                   , crc32    // (4)
                //,this.byteWorker.Fill( 11, 0x00 )
                ), 16
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");
 
            // current iv, reset to all zero after auth
            iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.symCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "17");
            sp.Add("MSG", "05" + "080000" + "010000" + this.hexConverter.Bytes2Hex( encryptedMsg ) );
            APDUResponse response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput( new byte[] { response.SW2 } );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");            
            string macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug( "result mac:[" + macHex + "]" );
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            //
            log.Debug("CommitTransaction(C7)...");
            // calculate cmac as next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { 0xC7 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            response = this.icash2Player.ProcessCommand("CommitTransaction");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { response.SW2 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
        }

        [Test]
        public void Test02ResetCardExpireDate1()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            SequenceParameter sp = new SequenceParameter();
            byte[] iv = null;
            byte[] sesKey = this.doAuth("B");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("WriteData with FNO 05...");
            byte[] rawData = new byte[] { 0x20,0x22,0x12,0x31 };
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "3D" + "05" + "000000" + "040000"
                )
               , rawData  // cmd(1) || fileNo(1) || offset(3) || length(3) || rawData(1)
            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            //
            byte[] decryptedMsg = this.byteWorker.Combine
            (
                rawData  // (4)
               , crc32    // (4)
                //,new byte[] { 0x00 }
               , this.byteWorker.Fill(8, 0x00)
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");

            // current iv, reset to all zero after auth
            iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.symCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "17");
            sp.Add("MSG", "05" + "000000" + "040000" + this.hexConverter.Bytes2Hex(encryptedMsg));
            APDUResponse response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            string macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            //
            log.Debug("CommitTransaction(C7)...");
            // calculate cmac as next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { 0xC7 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            response = this.icash2Player.ProcessCommand("CommitTransaction");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { response.SW2 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
        }

        [Test]
        public void Test05ReadCardStatus()
        {            
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] sesKey = this.doAuth("A");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");

            //byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyBHex);
            //byte[] divInput = this.getDivInput(this.uid);
            //log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            ////
            //this.keyDeriver.SetSeedKey(seedKey);
            //this.keyDeriver.DiverseInput(divInput);
            ////
            //this.divKey = this.keyDeriver.GetDerivedKey();
            //log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            ////
            //byte[] iv = SymCryptor.ConstZero;
            //this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            //this.symCryptor.SetKey(this.divKey);
            ////
            //log.Debug("Do AuthenticateAES...");
            //SequenceParameter sp = new SequenceParameter();
            //sp.Add("KNR", "0B");
            //APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            //log.Debug(response);
            //if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            //{
            //    log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            //}
            //this.symCryptor.SetIv(iv);
            //// get rndB from PICC
            //byte[] rndB = this.symCryptor.Decrypt(response.Data);
            //log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            //// get next iv
            //iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //// PCD Gen rndA
            //byte[] rndA = this.randWorker.GetBytes(16);
            //log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            ////
            //byte[] rndARndBROL8 = this.byteWorker.Combine
            //(
            //    rndA
            //  , this.byteWorker.RotateLeft(rndB, 1)
            //);
            //log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            //this.symCryptor.SetIv(iv);
            //byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            //log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            //// get next iv 
            //iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            //log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            ////
            //sp.Add("LEN", "20");
            //sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            //response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            //log.Debug(response);
            //byte[] encRndAROL8 = response.Data;
            //if (response.SW1 == 0x91 && response.SW2 == 0x00)
            //{
            //    log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            //}
            //// decrypt encRndAROL8
            //this.symCryptor.SetIv(iv);
            //byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            //log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            ////
            //byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            //Assert.AreEqual(expected, result);
            ////
            //byte[] sesKey = this.getSessionKey(rndA, rndB);
            //log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //// end mutual auth
            //
            SequenceParameter sp = new SequenceParameter();
            sp.Clear();
            sp.Add("FD", "05080000010000");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            byte[] iv = SymCryptor.ConstZero;
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            byte[] ivData = this.hexConverter.Hex2Bytes("BD" + "05" + "080000" + "010000");
            this.cMacWorker.DataInput(ivData);
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 1);
            log.Debug("card staus:[" + this.hexConverter.Bytes2Hex(readData) + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 1, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex( BitConverter.GetBytes( crcResult ) ) + "]");
            Assert.AreEqual( 0, crcResult );
        }

        [Test]
        public void Test01ReadCardExpireDate1()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }

            byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyBHex);
            byte[] divInput = this.getDivInput(this.uid);
            log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            //
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(divInput);
            //
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KNR", "0B");
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            this.symCryptor.SetIv(iv);
            // get rndB from PICC
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            // get next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // PCD Gen rndA
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            // get next iv 
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            // decrypt encRndAROL8
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            byte[] sesKey = this.getSessionKey(rndA, rndB);
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            // end mutual auth
            //
            sp.Clear();
            sp.Add("FD", "05000000040000");
            response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("BD" + "05" + "000000" + "040000");
            this.cMacWorker.DataInput(ivData);
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            log.Debug("card expire date1:[" + this.hexConverter.Bytes2Hex(readData) + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void TestReadWtCnt()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }

            byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyAHex);
            byte[] divInput = this.getDivInput(this.uid);
            log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            //
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(divInput);
            //
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KNR", "0A");
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            this.symCryptor.SetIv(iv);
            // get rndB from PICC
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            // get next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // PCD Gen rndA
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            // get next iv 
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            // decrypt encRndAROL8
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            byte[] sesKey = this.getSessionKey(rndA, rndB);
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            // end mutual auth
            //
            log.Debug("Get Writing card count...");
            response = this.icash2Player.ProcessSequence("GetWtCnt");
            log.Debug(response);
            
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("BD" + "0E" + "000000" + "040000");
            this.cMacWorker.DataInput(ivData);
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            // reverse to Big Endian
            uint counter = BitConverter.ToUInt32(this.byteWorker.Reverse(readData), 0);
            log.Debug("Write Counter:[" + counter + "]");
            
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void TestResetBalance()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyCHex);
            byte[] divInput = this.getDivInput(this.uid);
            log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            //
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(divInput);
            //
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //            
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            // iv reset to all zero
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KNR", "0C");
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            // get next iv from response data
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            //
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            // set next iv to CAPDU encrypted data
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            byte[] sesKey = this.getSessionKey(rndA, rndB);
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("Read balance from FNO 06...");
            response = this.icash2Player.ProcessSequence("GetValueNoAID");
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("6C" + "06");
            this.cMacWorker.DataInput(ivData);
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            // next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16 , 16 );
            //
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            uint balance = BitConverter.ToUInt32(readData, 0);
            log.Debug("balance:[" + balance + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
            // reset balance to big endian order
            byte[] rawData = readData;
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "DC" + "06"
                )
               , rawData  // cmd(1) || fileNo(1) || data(4)
            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            //
            byte[] decryptedMsg = this.byteWorker.Combine
            (
                rawData  // (4)
               , crc32   // (4)
               , this.byteWorker.Fill(8, 0x00)
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.symCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "11");
            sp.Add("MSG", "06" + this.hexConverter.Bytes2Hex(encryptedMsg));
            response = this.icash2Player.ProcessSequence("Debit", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            string macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            //
            log.Debug("CommitTransaction(C7)...");
            // calculate cmac as next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { 0xC7 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            response = this.icash2Player.ProcessCommand("CommitTransaction");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { response.SW2 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            
        }

        [Test]
        public void TestSetBalance()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyCHex);
            byte[] divInput = this.getDivInput(this.uid);
            log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            //
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(divInput);
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //            
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            // iv reset to all zero
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KNR", "0C");
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            // get next iv from response data
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            //
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            // set next iv to CAPDU encrypted data
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            byte[] sesKey = this.getSessionKey(rndA, rndB);
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            // reset iv
            iv = SymCryptor.ConstZero;
            //
            log.Debug("Credit balance to FNO 06...");

            uint balance = //0x00E0F500;
                800;
            log.Debug("balance:[" + balance + "]");
            //byte[] rawData = this.byteWorker.Reverse
            //(
            byte[] rawData = 
                BitConverter.GetBytes(balance)
            ;
            //);
            log.Debug("balance bytes:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
            //
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "0C" + "06"
                )
               , rawData  // cmd(1) || fileNo(1) || data(4)
            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            //
            byte[] decryptedMsg = this.byteWorker.Combine
            (
                rawData  // (4)
               , crc32   // (4)
               , this.byteWorker.Fill(8, 0x00)
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.symCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "11");
            sp.Add("MSG", "06" + this.hexConverter.Bytes2Hex(encryptedMsg));
            response = this.icash2Player.ProcessSequence("Credit", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            string macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            //
            log.Debug("CommitTransaction(C7)...");
            // calculate cmac as next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { 0xC7 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            response = this.icash2Player.ProcessCommand("CommitTransaction");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { response.SW2 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
        }

        [Test]
        public void TestGetChgUpLimit()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyBHex);
            byte[] divInput = this.getDivInput(this.uid);
            log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            //
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(divInput);
            //
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //            
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            // iv reset to all zero
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KNR", "0B");
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            // get next iv from response data
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            //
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            // set next iv to CAPDU encrypted data
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            byte[] sesKey = this.getSessionKey(rndA, rndB);
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            // reset iv
            iv = SymCryptor.ConstZero;
            //
            log.Debug("Get Charge Upper limit from FNO 0C...");
            sp.Clear();
            sp.Add("FD", "0C000000040000");            
            response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.SetMacKey(sesKey);
            byte[] macData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "BD" + "0C" + "000000040000"
                )
            );
            this.cMacWorker.DataInput(macData);
            iv = this.cMacWorker.GetMac();
            // get response data
            this.symCryptor.SetIv( iv );
            this.symCryptor.SetKey( sesKey );
            byte[] decryptedData = this.symCryptor.Decrypt(response.Data);
            log.Debug("Decrypted Response:[" + this.hexConverter.Bytes2Hex(decryptedData) + "]");

            byte[] limitBytes = this.byteWorker.SubArray(decryptedData, 0, 4);
            log.Debug("Charge Upper Limit Hex:[" + this.hexConverter.Bytes2Hex(limitBytes) + "]");
            uint limit = Convert.ToUInt32(this.hexConverter.Bytes2Hex(limitBytes));
            log.Debug("Charge Upper Limit:[" + limit + "]"); 
            byte[] crcBytes = this.byteWorker.SubArray(decryptedData, 4, 4);
            // crc check
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcBytes) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    limitBytes  
                  , new byte[] { response.SW2 } // status
                  , crcBytes
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void TestSetWtCnt()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyBHex);
            byte[] divInput = this.getDivInput(this.uid);
            log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            //
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(divInput);
            //
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //            
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            // iv reset to all zero
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KNR", "0B");
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            // get next iv from response data
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            //
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            // set next iv to CAPDU encrypted data
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            byte[] sesKey = this.getSessionKey(rndA, rndB);
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("WriteData with FN. 0E...");
            byte[] rawData = new byte[] { 0x00,0x00,0x00,0x07 };
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "3D" + "0E" + "000000" + "040000"
                )
               , rawData  // cmd(1) || fileNo(1) || offset(3) || length(3) || rawData(1)
            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            //
            byte[] decryptedMsg = this.byteWorker.Combine
            (
                 rawData  // (4)
               , crc32    // (4)
               , this.byteWorker.Fill(8, 0x00)
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");

            // current iv, reset to all zero after auth
            iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.symCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "17");
            sp.Add("MSG", "0E" + "000000" + "040000" + this.hexConverter.Bytes2Hex(encryptedMsg));
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            string macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            // standard files don't need commit            
        }

        [Test]
        public void TestReadTxSn()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }

            byte[] seedKey = this.hexConverter.Hex2Bytes(seedKeyBHex);
            byte[] divInput = this.getDivInput(this.uid);
            log.Debug("DivInput:[" + this.hexConverter.Bytes2Hex(divInput) + "]");
            //
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(divInput);
            //
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("KNR", "0B");
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            this.symCryptor.SetIv(iv);
            // get rndB from PICC
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            // get next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // PCD Gen rndA
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            // get next iv 
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            // decrypt encRndAROL8
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            byte[] sesKey = this.getSessionKey(rndA, rndB);
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            // end mutual auth
            //
            log.Debug("Get Tx Sn from FN 07...");
            sp.Clear();
            sp.Add("FD", "07");
            response = this.icash2Player.ProcessSequence("GetValueNoAID", sp);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("6C" + "07");
            this.cMacWorker.DataInput(ivData);
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            // next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            uint balance = BitConverter.ToUInt32(readData, 0);
            log.Debug("Tx Sn:[" + balance + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void TestGetPayInfo()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            //
            byte[] sesKey = this.doAuth("B");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("Get Payment Sn from FN 0A...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("FD", "0A");
            APDUResponse response = this.icash2Player.ProcessSequence("GetValueNoAID", sp);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("6C" + "0A");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            // next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            uint paySn = BitConverter.ToUInt32(readData, 0);
            log.Debug("Payment Sn:[" + paySn + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
            // Get Payment total from FN: 0B
            sp.Clear();
            sp.Add("FD", "0B");
            response = this.icash2Player.ProcessSequence("GetValueNoAID", sp);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            log.Debug("iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.SetMacKey(sesKey);
            ivData = this.hexConverter.Hex2Bytes("6C" + "0B");
            this.cMacWorker.DataInput(ivData);
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            decResponseData = this.symCryptor.Decrypt(response.Data);
            // next iv, no use
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);            
            //
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            uint payTot = BitConverter.ToUInt32(readData, 0);
            log.Debug("Payment Tatal:[" + payTot + "]");
            crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void TestGetChargeInfo()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            
            byte[] sesKey = this.doAuth( "C");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("Get Charge Sn from FN 08...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("FD", "08");
            APDUResponse response = this.icash2Player.ProcessSequence("GetValueNoAID", sp);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("6C" + "08");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] decResponseData = this.symCryptor.Decrypt(response.Data);
            // next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            byte[] readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            uint chargeSn = BitConverter.ToUInt32(readData, 0);
            log.Debug("Charge Sn:[" + chargeSn + "]");
            byte[] crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            uint crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
            // Get Charge total from FN: 09
            sp.Clear();
            sp.Add("FD", "09");
            response = this.icash2Player.ProcessSequence("GetValueNoAID", sp);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.SetMacKey(sesKey);
            ivData = this.hexConverter.Hex2Bytes("6C" + "09");
            this.cMacWorker.DataInput(ivData);
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            decResponseData = this.symCryptor.Decrypt(response.Data);
            // next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            //
            log.Debug("Decrypted response data:[" + this.hexConverter.Bytes2Hex(decResponseData) + "]");
            readData = this.byteWorker.SubArray(decResponseData, 0, 4);
            uint chargeTot = BitConverter.ToUInt32(readData, 0);
            log.Debug("Charge Total:[" + chargeTot + "]");
            crcResponse = this.byteWorker.SubArray(decResponseData, 4, 4);
            log.Debug("CRC32 Response:[" + this.hexConverter.Bytes2Hex(crcResponse) + "]");
            //
            crcResult = this.nxpCrc32Worker.ComputeChecksum
            (
                this.byteWorker.Combine
                (
                    readData  // decrypted data
                  , new byte[] { response.SW2 } // status
                  , crcResponse
                )
            );
            log.Debug("Verify CRC32  :[" + this.hexConverter.Bytes2Hex(BitConverter.GetBytes(crcResult)) + "]");
            Assert.AreEqual(0, crcResult);
        }

        [Test]
        public void Test03GetAutoloadFlag()
        {
            log.Debug("Get Autoload...");
            APDUResponse response = this.icash2Player.ProcessSequence("GetAutoload");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Autoload:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void Test04ResetAutoloadFlag()
        {
            // reset first byte of 0x13 to 0x10
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] sesKey = this.doAuth("2");             
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("WriteData with FNO 13...");

            // get CRC
            byte[] rawData = new byte[] { 0x10 };
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "3D" + "13" + "000000" + "010000"
                )
               , rawData  // cmd(1) || fileNo(1) || offset(0) || length(3) || rawData(1)
            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");

            // Encrypt raw data || CRC
            byte[] decryptedMsg = this.byteWorker.Combine
            (
                rawData  // (1)
               , crc32    // (4)
                //,new byte[] { 0x00 }
               , this.byteWorker.Fill(11, 0x00)
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");

            // current iv, reset to all zero after auth
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.symCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // get next iv, update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            SequenceParameter sp = new SequenceParameter();
            //sp.Clear();
            sp.Add("LEN", "17");
            sp.Add("MSG", "13" + "000000" + "010000" + this.hexConverter.Bytes2Hex(encryptedMsg));
            APDUResponse response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac with new iv , then update iv
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            string macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            //
            log.Debug("CommitTransaction(C7)...");
            // calculate cmac as next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { 0xC7 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            response = this.icash2Player.ProcessCommand("CommitTransaction");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { response.SW2 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);

        }

        [Test]
        public void Test07SetNoPointFlag()
        {
            // reset offset 0x12 byte of 0x13 to 0x10
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] sesKey = this.doAuth("2");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("WriteData with FNO 13...");

            // get CRC
            byte[] rawData = new byte[] { 0x01 };
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "3D" + "13" + "0C0000" + "010000"
                )
               , rawData  // cmd(1) || fileNo(1) || offset(3) || length(3) || rawData(1)
            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");

            // Encrypt raw data || CRC
            byte[] decryptedMsg = this.byteWorker.Combine
            (
                 rawData  // (1)
               , crc32    // (4)
               , this.byteWorker.Fill(11, 0x00)
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");

            // current iv, reset to all zero after auth
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.symCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // get next iv, update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            SequenceParameter sp = new SequenceParameter();
            //sp.Clear();
            sp.Add("LEN", "17");
            sp.Add("MSG", "13" + "0C0000" + "010000" + this.hexConverter.Bytes2Hex(encryptedMsg));
            APDUResponse response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac with new iv , then update iv
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            string macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);
            //
            log.Debug("CommitTransaction(C7)...");
            // calculate cmac as next iv
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { 0xC7 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            response = this.icash2Player.ProcessCommand("CommitTransaction");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // check cmac
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput
            (
                new byte[] { response.SW2 }
            );
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            macHex = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(iv, 0, 8));
            log.Debug("result mac:[" + macHex + "]");
            Assert.AreEqual(this.hexConverter.Bytes2Hex(response.Data), macHex);

        }

        //[Test]
        public void TestCMac()
        {
            this.symCryptor = this.ctx["aesCryptor"] as SymCryptor;
            this.symCryptor.SetKey(this.hexConverter.Hex2Bytes("56698645E5062BCB7966F042932E3D7F"));
            this.symCryptor.SetIv( this.hexConverter.Hex2Bytes("21885311B15CD46AFEC71C16C4AE37D9"));
            byte[] decrypted = this.byteWorker.Combine
            (
                new byte[] { 0x00, 0x80 }
               , this.byteWorker.Fill(14, 0x00)
            );
            byte[] result = this.symCryptor.Encrypt( decrypted );
            log.Debug( this.hexConverter.Bytes2Hex( result ) );
            //this.cMacWorker.SetMacKey(this.hexConverter.Hex2Bytes("56698645E5062BCB7966F042932E3D7F"));
            //this.cMacWorker.DataInput(new byte[] { 0x00 } );
            //result = this.cMacWorker.GetMac();
            //log.Debug(this.hexConverter.Bytes2Hex(result));
        }

        [TearDown]
        public void TearDown()
        {
            this.icash2Player.CardNative.Disconnect(DISCONNECT.Reset);
        }

        private byte[] getDivInput(byte[] uid)
        {
            return this.byteWorker.Combine
            (
                  uid
                , Encoding.ASCII.GetBytes("ICASH")
                , uid
                , Encoding.ASCII.GetBytes("ICASH")
                , uid
            );
        }

        private byte[] getSessionKey(byte[] rndA, byte[] rndB)
        {
            return this.byteWorker.Combine
            (
                 this.byteWorker.SubArray(rndA, 0, 4)
                , this.byteWorker.SubArray(rndB, 0, 4)
                , this.byteWorker.SubArray(rndA, 12, 4)
                , this.byteWorker.SubArray(rndB, 12, 4)
            );
        }

        private byte[] getSeedKey(string seedKeyId)
        {            
            byte[] seedKey = null;
            if (seedKeyId.Equals("0"))
            {
                seedKey = this.hexConverter.Hex2Bytes( this.seedKey0Hex );
            }
            else if (seedKeyId.Equals("2"))
            {
                seedKey = this.hexConverter.Hex2Bytes(this.seedKey2Hex);
            }
            else if (seedKeyId.Equals("A"))
            {
                seedKey = this.hexConverter.Hex2Bytes( this.seedKeyAHex );
            }
            else if (seedKeyId.Equals("B"))
            {
                seedKey = this.hexConverter.Hex2Bytes( this.seedKeyBHex );
            }
            else if (seedKeyId.Equals("C"))
            {
                seedKey = this.hexConverter.Hex2Bytes( this.seedKeyCHex );
            }
            else if( seedKeyId.Equals("Master"))
            {
                seedKey = this.hexConverter.Hex2Bytes(this.seedKeyMasterHex);
            }
            else
            {
                throw new Exception("Seedkey:[0" + seedKeyId + "] not found...");
            }
            return seedKey;
        }

        private byte[] doAuth(string seedKeyId)
        {            
            this.keyDeriver.SetSeedKey(this.getSeedKey(seedKeyId));
            
            this.keyDeriver.DiverseInput(this.getDivInput(this.uid));
            this.divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(this.divKey) + "]");
            //            
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor = ctx["aesCryptor"] as SymCryptor;
            this.symCryptor.SetKey(this.divKey);
            //
            log.Debug("Do AuthenticateAES...");
            // get rndB from PICC
            SequenceParameter sp = new SequenceParameter();
            if ("Master".Equals(seedKeyId))
            {
                sp.Add("AID", "000000");
                sp.Add("KNR", "00");
            }
            else
            {
                sp.Add("AID", "118716");
                sp.Add("KNR", "0" + seedKeyId);
            }
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
            //log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                log.Debug("encRndB:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            this.symCryptor.SetIv(iv);
            byte[] rndB = this.symCryptor.Decrypt(response.Data);
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            // get next iv
            iv = this.byteWorker.SubArray(response.Data, response.Data.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // PCD Gen rndA
            byte[] rndA = this.randWorker.GetBytes(16);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            //log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            this.symCryptor.SetIv(iv);
            byte[] encRndARndBROL8 = this.symCryptor.Encrypt(rndARndBROL8);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            // get next iv 
            iv = this.byteWorker.SubArray(encRndARndBROL8, encRndARndBROL8.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Add("LEN", "20");
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            // decrypt encRndAROL8
            this.symCryptor.SetIv(iv);
            byte[] result = this.symCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            return this.getSessionKey(rndA, rndB);
        }
    }
}
