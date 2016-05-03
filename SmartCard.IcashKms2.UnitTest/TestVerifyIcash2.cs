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
using Kms.Utility;

namespace SmartCard.Player.UnitTest
{
    [TestFixture]
    public class TestVerifyIcash2
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestVerifyIcash2));
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
        private Iso14443ACrcWorker nxpCrc16Worker = null;
        private IDateUtility dateUtility = null;
        private IStrHelper strHelper = null;
        private byte[] uid = null;

        private IDictionary<string, string> dicKey = new Dictionary<string, string>()
		{
		    { "origCMK0Hex",   "00000000000000000000000000000000"}
           ,{ "origAMK0Hex",   "00000000000000000000000000000000"}
           ,{ "seedKeyCMKHex", "DCA15D2F402E1C14F069C80FAAA1002F"}
		   ,{ "seedKey0Hex",   "DA86D23592B1CAB3740B298D2C8E5CC3"}
           ,{ "seedKey1Hex",   "301F6B3CC357993B9C6A7BB826EF123E"}
           ,{ "seedKey2Hex",   "A40A37803FEA38852FEA19FB372538F3"}
           ,{ "seedKey3Hex",   "C95AC14B296F90E8CF33680177BE7F1D"}
           ,{ "seedKey8Hex",   "C57B1C1771DFC9FCA249302460A27E31"}
           ,{ "seedKey9Hex",   "C2135DF8F2AAFA0D3E0FB82D846F5A53"}
		   ,{ "seedKeyAHex",   "FDA01F10E42489733FE1EE514AC55E92"}
           ,{ "seedKeyBHex",   "EEEA4C617D2880C83BC2358AF645EBDC"}
           ,{ "seedKeyCHex",   "082CBB7C855C366CCFBF4A07444BA989"}
		}
        ;
        IDictionary<string, string> dicFNR = new Dictionary<string, string>() 
        {
               {"01","000310AF040000"}
              ,{"02","010320AF0F0000"}
              ,{"03","010320EF080000"}
              ,{"04","010330AF280000"}
              ,{"05","0103B0AF090000"}
              //,{"06","0203C0EB00000000FFE0F5050000000001"}
              ,{"06","0203C0EB9CFFFFFFFFE0F5050000000001"}
              ,{"07","0203B0FC00000000FFE0F5050000000001"}
              ,{"08","0203C0FF00000000FFE0F5050000000001"}
              ,{"09","0203C0FF00000000FFE0F5050000000001"}
              ,{"0A","0203B0FF00000000FFE0F5050000000001"}
              ,{"0B","0203B0FF00000000FFE0F5050000000001"}
              ,{"0C","010320BF040000"}
              ,{"0D","0403B0EC3300000D0000"}
              ,{"0E","0003B0AF040000"}
              ,{"0F","000320EF020000"}
              ,{"10","0103B0EC330000"}
              ,{"11","0103B0AF600000"}
              ,{"12","0103B0AF600000"}
              ,{"13","010320EC100000"}
              ,{"14","010320EC010000"}
              ,{"15","0103B0AF600000"}
              ,{"16","0103B0AF600000"}
              ,{"17","0103908F360000"}
              ,{"18","0103908F360000"}
              ,{"19","0103908F360000"}
              ,{"1A","0103908F360000"}
              ,{"1B","0103908F100000"}
              ,{"1C","0403908F130000030000"}
              ,{"1D","0103908F600000"}
              ,{"1E","0103908F600000"}
              ,{"1F","0103908F600000"}
        };

        IDictionary<string, string> dicCardMap = new Dictionary<string, string>()
        {
            { "04296DC23D2480","7416140993000001" }
           ,{ "04116DC23D2480","7416140992000002" }
           ,{ "04856DC23D2480","7416140998000003" }
           ,{ "04556EC23D2480","7416140996000004" }
           ,{ "0478414ACC2280","7416140998000005" }
           ,{ "0457414ACC2280","7416140990000006" }
           ,{ "0461404ACC2280","7416140995000007" }
           ,{ "046B404ACC2280","7416140992000008" }
           ,{ "0462424ACC2280","7416140995000009" }
           ,{ "0435404ACC2280","7416140997000010" }
           ,{ "044243C23D2480","7111120039000015" }
           ,{ "04783FC23D2480","7416140991000013" }
           ,{ "04796DC23D2480","7611140998001267" }
           ,{ "04608CCA3D2480","7117120211000029" }
           ,{ "0428107A722B80","7115120010000099" }
           ,{ "04182B4AFA3680","7115120011000099" }
           ,{ "041B8372581F80","7115120012000099" }
           ,{ "041C2072581F80","7115120013000099" }
           ,{ "04932C820A3580","7611140992001299" }
           ,{ "045822820A3580","7611140993001300" }
           ,{ "045542C23D2480","7416140992000008" }
           ,{ "045C335A472180","7115120016000099" }
           ,{ "045F335A472180","7115120017000099" }
           ,{ "045A335A472180","7115120018000099" }
           ,{ "042A1E92C02D80","7111120039000015" }
           ,{ "042B0792C02D80","7111120039000016" }
           ,{ "044706DAF32880","7515130015000074" }
        }; 

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
            this.nxpCrc16Worker = ctx["nxpCrc16Worker"] as Iso14443ACrcWorker;
            this.nxpCrc32Worker = ctx["nxpCrc32Worker"] as ICrcWorker<uint>;
            this.tDesCryptor = ctx["nxpTDesCryptor"] as ISymCryptor;
            this.dateUtility = ctx["dateUtility"] as IDateUtility;
            this.strHelper = ctx["strHelper"] as IStrHelper;
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
                }
                catch (Exception ex)
                {
                    log.Debug(ex.Message);
                }
            }
            if (!chkOK)
            {
                log.Debug("No match card exists!");
                return;
            }
        }

        [Test]
        public void Test01ValidCMK()
        {
            if (this.uid == null)
            {
                throw new Exception("Read UID fail...");
            }
            APDUResponse response = null;
            //
            response = this.icash2Player.ProcessSequence("SelectPICC");
            log.Debug(response);
            //           
            byte[] sesKey = this.doAuth("seedKeyCMKHex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
        }

        [Test]
        public void Test02ValidCMKSettings()
        {
            string expected = "0F01";//"0901";
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            log.Debug("Get CMK Settings...");
            response = this.icash2Player.ProcessSequence("SelectPICC");
            //
            byte[] sesKey = this.doAuth("seedKeyCMKHex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //            
            response = this.icash2Player.ProcessSequence("GetKeySettings");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // update iv
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(SymCryptor.ConstZero);
            byte[] ivData = this.hexConverter.Hex2Bytes("45");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // check if cmac ok
            //   update iv
            this.cMacWorker.SetIv(iv);
            // data || status
            byte[] macData =
                this.byteWorker.Combine
                (
                    this.byteWorker.SubArray(response.Data, 0, 2)
                   , new byte[] { response.SW2 }
                );
            this.cMacWorker.DataInput(macData);
            iv = this.cMacWorker.GetMac();
            // get first 8 bytes of iv
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            byte[] cmac = byteWorker.SubArray(iv, 0, 8);
            log.Debug("cmac:[" + this.hexConverter.Bytes2Hex(cmac) + "]");
            Assert.AreEqual(this.byteWorker.SubArray(response.Data, 2, 8), cmac);
            Assert.AreEqual(expected, this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, 0, 2)));
        }

        [Test]
        public void Test02ValidAPKs()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            log.Debug("Select AID 118716...");
            sp.Clear();
            sp.Add("AID", "118716");
            response = this.icash2Player.ProcessSequence("SelectAID", sp);
            //
            byte[] sesKey = null;
            string keyName = "";
            //
            keyName = "seedKey0Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            keyName = "seedKey1Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            keyName = "seedKey2Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            keyName = "seedKey3Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            keyName = "seedKey8Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            keyName = "seedKey9Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            keyName = "seedKeyAHex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            ////
            keyName = "seedKeyBHex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            keyName = "seedKeyCHex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
        }
                
        [Test]
        public void Test08ValidAMKSettings()
        {
            string expected = "098E";
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            log.Debug("Get AID 118716 Master Key Settings...");
            sp.Clear();
            sp.Add("AID", "118716");
            response = this.icash2Player.ProcessSequence("SelectAID", sp);
            log.Debug(response);
            //
            byte[] sesKey = this.doAuth("seedKey0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //            
            response = this.icash2Player.ProcessSequence("GetKeySettings");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // update iv
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(SymCryptor.ConstZero);
            byte[] ivData = this.hexConverter.Hex2Bytes("45");
            this.cMacWorker.DataInput(ivData);
            byte[] iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // check if cmac ok
            //   update iv
            this.cMacWorker.SetIv(iv);
            // data || status
            byte[] macData =
                this.byteWorker.Combine
                (
                    this.byteWorker.SubArray(response.Data, 0, 2)
                   , new byte[] { response.SW2 }
                );
            this.cMacWorker.DataInput(macData);
            iv = this.cMacWorker.GetMac();
            // get first 8 bytes of iv
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            byte[] cmac = byteWorker.SubArray(iv, 0, 8);
            log.Debug("cmac:[" + this.hexConverter.Bytes2Hex(cmac) + "]");
            Assert.AreEqual(this.byteWorker.SubArray(response.Data, 2, 8), cmac);
            Assert.AreEqual(expected, this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, 0, 2)));
            /*
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
            {
                log.Debug(arrayLog[nI].ToString());
            }
            */
        }

        /// <summary>
        ///  Check after AMK Authentication
        /// </summary>
        [Test]
        public void Test02ValidFileSettings()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //            
            byte[] sesKey = null;
            string keyName = "";
            //
            keyName = "seedKey0Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.cMacWorker.SetMacKey(sesKey);
            byte[] iv = this.byteWorker.Fill(16, 0x00);
            IList<string> listFNR = new List<string>() 
            {
                  "01", "02", "03", "04", "05", "06", "07", "08"
                , "09", "0A", "0B", "0C", "0D", "0E", "0F", "10"
                , "11", "12", "13", "14", "15", "16", "17", "18"
                , "19", "1A", "1B", "1C", "1D", "1E", "1F"
            };
            //
            byte[] macData = null;
            byte[] mac = null;
            byte[] fSet = null;
            foreach (string fNR in listFNR)
            {
                macData = new byte[] { 0xF5, this.hexConverter.Hex2Byte(fNR) };
                this.cMacWorker.SetIv(iv);
                this.cMacWorker.DataInput(macData);
                mac = this.cMacWorker.GetMac();
                // set next iv
                iv = mac;
                //
                sp.Clear();
                sp.Add("FNR", fNR);
                response = this.icash2Player.ProcessSequence("GetFileSettings", sp);
                // check mac       
                fSet = this.byteWorker.SubArray(response.Data, 0, response.Data.Length - 8);
                macData = this.byteWorker.Combine
                (
                    fSet, new byte[] { response.SW2 }
                );
                this.cMacWorker.SetIv(iv);
                this.cMacWorker.DataInput(macData);
                // next iv
                iv = mac = this.cMacWorker.GetMac();
                Assert.AreEqual(this.byteWorker.SubArray(mac, 0, 8), this.byteWorker.SubArray(response.Data, response.Data.Length - 8, 8));
                string fsStr = this.hexConverter.Bytes2Hex(fSet);
                log.Debug("FNR:[" + fNR + "]: " + fsStr);
                string resultFileSet = fsStr.Substring( 0, this.dicFNR[fNR].Length );
                Assert.AreEqual(this.dicFNR[fNR], resultFileSet);
            }
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
            if (this.dicKey.ContainsKey(seedKeyId))
            {
                seedKey = this.hexConverter.Hex2Bytes(this.dicKey[seedKeyId]);

            }
            else
            {
                throw new Exception("Seedkey:[" + seedKeyId + "] not found...");
            }
            return seedKey;
        }

        private byte[] getDivKey(string seedKeyId)
        {
            byte[] seedKey = this.getSeedKey(seedKeyId);
            if (
                 "origAMK0Hex".Equals(seedKeyId)
              || "origCMK0Hex".Equals(seedKeyId)
            )
            {
                log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(seedKey) + "]");
                return seedKey;
            }
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInput(this.uid));
            byte[] divKey = this.keyDeriver.GetDerivedKey();
            log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(divKey) + "]");
            return divKey;
        }
  

        

        
        /// <summary>
        ///  Do AuthenticateAES (128), Get Session Key
        /// </summary>
        /// <param name="seedKeyId">use seedKeyId to get seedKey</param>
        /// <returns>session Key</returns>
        private byte[] doAuth(string seedKeyId)
        {
            //            
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor = ctx["symCryptor"] as SymCryptor;
            this.symCryptor.SetKey(this.getDivKey(seedKeyId));
            //
            log.Debug("Do AuthenticateAES...");
            // get rndB from PICC
            SequenceParameter sp = new SequenceParameter();
            if (
                "seedKeyCMKHex".Equals(seedKeyId)
             || "origCMK0Hex".Equals(seedKeyId)
            )
            {
                sp.Add("AID", "000000");
                sp.Add("KNR", "00");
            }
            else if ("origAMK0Hex".Equals(seedKeyId))
            {
                sp.Add("AID", "118716");
                sp.Add("KNR", "00");
            }
            else
            {
                sp.Add("AID", "118716");
                string knr = "0" + seedKeyId.Substring(7, 1);
                sp.Add("KNR", knr);
            }
            // Card Gen rndB
            APDUResponse response = this.icash2Player.ProcessSequence("AuthenticateAES", sp);
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
            Assert.AreEqual(response.SW2, 0x00);

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

        /// <summary>
        /// Auth default CMK TDES 2key allzero
        /// </summary>
        /// <returns></returns>
        private byte[] authOrigCMK()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;

            // 2key, 3Des
            // Authenticate(3)DES with Default Card Master Key
            sp.Clear();
            sp.Add("AID", "000000");
            sp.Add("KN", "00");
            response = this.icash2Player.ProcessSequence("Authenticate(3)DES", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            byte[] encRndB = response.Data;
            byte[] iv = this.byteWorker.Fill(8, 0x00);
            this.tDesCryptor.SetIv(iv);
            byte[] kx = this.hexConverter.Hex2Bytes(this.dicKey["origCMK0Hex"]);
            this.tDesCryptor.SetKey(kx);
            //
            byte[] rndB = this.tDesCryptor.Decrypt(encRndB);
            log.Debug("rndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");

            // PCD Gen rndA
            byte[] rndA = this.randWorker.GetBytes(8);
            log.Debug("rndA:[" + this.hexConverter.Bytes2Hex(rndA) + "]");
            //
            byte[] rndARndBROL8 = this.byteWorker.Combine
            (
                rndA
              , this.byteWorker.RotateLeft(rndB, 1)
            );
            log.Debug("rndARndBROL8:[" + this.hexConverter.Bytes2Hex(rndARndBROL8) + "]");

            byte[] encRndARndBROL8 = this.tDesCryptor.Encrypt(rndARndBROL8);
            log.Debug("encRndARndBROL8:[" + this.hexConverter.Bytes2Hex(encRndARndBROL8) + "]");
            //
            //sp.Add("LEN", "10"); // 0x10
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encRndARndBROL8));
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            log.Debug(response);
            byte[] encRndAROL8 = response.Data;
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("encRndAROL8:[" + this.hexConverter.Bytes2Hex(encRndAROL8) + "]");
            }
            byte[] rndAROL8 = this.tDesCryptor.Decrypt(encRndAROL8);
            log.Debug("rndAROL8:[" + this.hexConverter.Bytes2Hex(rndAROL8) + "]");
            Assert.AreEqual(this.byteWorker.RotateRight(rndAROL8, 1), rndA);
            // K1 == K2, SesKey = rndA[0..3] || rndB[0..3] || rndA[0..3] || rndB[0..3]
            return this.byteWorker.Combine
            (
                this.byteWorker.SubArray(rndA, 0, 4)
               , this.byteWorker.SubArray(rndB, 0, 4)
               , this.byteWorker.SubArray(rndA, 0, 4)
               , this.byteWorker.SubArray(rndB, 0, 4)
            );
        }
    }
}
