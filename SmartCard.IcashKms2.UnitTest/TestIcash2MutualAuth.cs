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
using Kms.Crypto;
using Kms2.Crypto;

namespace SmartCard.IcashKms2.UnitTest
{
    [TestFixture]
    public class TestIcash2MutualAuth
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestIcash2MutualAuth));
        //
        private bool chkOK = false;
        private IApplicationContext ctx;
        private IKey2Deriver key2Deriver;
        private IHexConverter hexConverter;
        private IByteWorker byteWorker;
        private IRandWorker randWorker;
        //
        private ICard cardNative;
        private APDUPlayer icash2Player = null;
        //
        private ISymCryptor aesCryptor = null;
        private ICMacWorker cMacWorker = null;
        private ICrcWorker<uint> nxpCrc32Worker = null;
        //
        private byte[] uid = null;
        //private byte[] divKey = null;

        private string seedKeyMaster = "2ICH3F000004A";
        private string seedKey0 = "2ICH3F000036A";
        private string seedKeyA = "2ICH3F000032A";
        private string seedKeyB = "2ICH3F000033A";
        private string seedKeyC = "2ICH3F000034A";
        private string seedKey1 = "2ICH3F000037A";
        private string seedKey2 = "2ICH3F000038A";

        private ISymCryptor tDesCryptor = null;

        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.key2Deriver = ctx["icash2KeyDeriver"] as IKey2Deriver;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.icash2Player = ctx["apduPlayer"] as APDUPlayer;
            this.randWorker = ctx["randWorker"] as IRandWorker;
            this.cMacWorker = ctx["aes128CMacWorker"] as ICMacWorker;
            this.nxpCrc32Worker = ctx["nxpCrc32Worker"] as ICrcWorker<uint>;
            this.tDesCryptor = ctx["tripleDesCbcCryptor"] as ISymCryptor;
            this.aesCryptor = ctx["aesCryptor"] as ISymCryptor;
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
                    if (!( reader.StartsWith("NXP PR533") || reader.StartsWith("SCM Microsystems SCL3711 reader & NFC device") ||  reader.StartsWith("CASTLES EZ710BU_CL")))
                    {
                        log.Debug("Skip: [" + reader + "]....");
                        continue;
                    }
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
                        this.uid = this.getUid();                        
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
                log.Error("No match card exists!");
                throw new Exception( "No match card exists!" );
            }
        }
        
        [Test]
        public void Test01ReadCardStatus()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            byte[] sesKey = this.doAuth("B");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            // end mutual auth

            SequenceParameter sp = new SequenceParameter();
            sp.Add("FD", "05080000010000");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes("BD" + "05" + "080000" + "010000");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.aesCryptor.SetIv(iv);
            this.aesCryptor.SetKey(sesKey);
            byte[] decResponseData = this.aesCryptor.Decrypt(response.Data);
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
        public void Test02SetCardStatus()
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
            byte[] rawData = new byte[] { 0x01 };  // enable card status
            byte[] crcData = this.byteWorker.Combine
            (
                this.hexConverter.Hex2Bytes
                (
                    "3D" + "05" + "080000" + "010000"
                )
               , rawData  // cmd(1) || fileNo(1) || offset(3) || length(3) || rawData(1)
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
                ), 16
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");

            // current iv, reset to all zero after auth
            iv = SymCryptor.ConstZero;
            this.aesCryptor.SetIv(iv);
            this.aesCryptor.SetKey(sesKey);
            byte[] encryptedMsg = this.aesCryptor.Encrypt(decryptedMsg);
            log.Debug("Encrypted DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(encryptedMsg) + "]");

            // update iv
            iv = this.byteWorker.SubArray(encryptedMsg, encryptedMsg.Length - 16, 16);
            log.Debug("updated iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("LEN", "17");
            sp.Add("MSG", "05" + "080000" + "010000" + this.hexConverter.Bytes2Hex(encryptedMsg));
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
        public void Test03ReadCardExpireDate1()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }

            byte[] sesKey = this.doAuth("B");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            // end mutual auth

            SequenceParameter sp = new SequenceParameter();
            //
            sp.Clear();
            sp.Add("FD", "05000000040000");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadData", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // cmac as next iv, get next iv
            this.cMacWorker.SetMacKey(sesKey);
            byte[] ivData = this.hexConverter.Hex2Bytes( "BD" + "05" + "000000" + "040000" );
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            this.aesCryptor.SetIv(iv);
            this.aesCryptor.SetKey(sesKey);
            byte[] decResponseData = this.aesCryptor.Decrypt(response.Data);
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
                   
        [TearDown]
        public void TearDown()
        {
            this.icash2Player.CardNative.Disconnect(DISCONNECT.Reset);
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

        private string getSeedKey(string seedKeyId)
        {            
            string seedKey = null;
            if (seedKeyId.Equals("0"))
            {
                seedKey = this.seedKey0;
            }
            else if (seedKeyId.Equals("1"))
            {
                seedKey = this.seedKey1;
            }
            else if (seedKeyId.Equals("2"))
            {
                seedKey = this.seedKey2;
            }
            else if (seedKeyId.Equals("A"))
            {
                seedKey = this.seedKeyA;
            }
            else if (seedKeyId.Equals("B"))
            {
                seedKey = this.seedKeyB;
            }
            else if (seedKeyId.Equals("C"))
            {
                seedKey = this.seedKeyC;
            }
            else if( seedKeyId.Equals("Master"))
            {
                seedKey = this.seedKeyMaster;
            }
            else
            {
                throw new Exception("Seedkey:[0" + seedKeyId + "] not found...");
            }
            return seedKey;
        }

        private byte[] doAuth(string seedKeyId)
        {            
            this.key2Deriver.SetSeedKey(this.getSeedKey(seedKeyId));            
            this.key2Deriver.DiverseInput(this.uid);
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
            byte[] iv = SymCryptor.ConstZero;
            byte[] rndB = this.key2Deriver.Decrypt( iv, response.Data);
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            // get next iv, from rapdu last 16 bytes
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
            log.Debug("RndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");
            byte[] encRndARndBROL8 = this.key2Deriver.Encrypt( iv, rndARndBROL8 );
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            // get next iv, from prev capdu
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
            byte[] result = this.key2Deriver.Decrypt( iv, encRndAROL8 );
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(result) + "]");
            //
            byte[] expected = this.byteWorker.RotateLeft(rndA, 1);
            Assert.AreEqual(expected, result);
            //
            return this.getSessionKey(rndA, rndB);
        }

        private byte[] getUid()
        {
            log.Debug("Get Version...");
            APDUResponse response = this.icash2Player.ProcessSequence("GetVersion");
            //log.Debug(response);
            //APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            //for (int nI = 0; nI < arrayLog.Length; nI++)
            //{
            //    log.Debug(arrayLog[nI].ToString());
            //}
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("UID:[" + this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, 0, 7)) + "]");
                return this.byteWorker.SubArray(response.Data, 0, 7);
            }
            else
            {
                log.Error("GetVersion Fail...");
                return null;
            }
        }
    }
}
