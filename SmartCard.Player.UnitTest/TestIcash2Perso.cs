using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using System.Xml;
using System.Linq;
using System.Xml.Linq;
using System.Xml.XPath;
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
using Kms2.Crypto.Utility;

namespace SmartCard.Player.UnitTest
{
    [TestFixture]
    public class TestIcash2Perso
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestIcash2Perso));
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
         //,{ "seedKeyAHex",   "ADA01F10E42489733FE1EE514AC55E92"} // change seed key A to 
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
          // ,{ "04608CCA3D2480","7117120211000029" }
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
           ,{ "046420E2F32880", "7414144448000001"}
           ,{ "043712E2F32880", "7414144443000002"}
           ,{ "045319A2DA2C80", "7515130012000035"} //045404A2DA2C80
           ,{ "047A16A2DA2C80", "7515130015000045"}
           ,{ "043A414ACC2280", "7413149982000000"}
           ,{ "0452404ACC2280", "7413149981000001"}
           //// iiiedc
           //,{ "047F37A2DD2F80", "7211130986000010"}
           //,{ "04187222EB3580", "7511130991000084"}
           //,{ "04351D22162980", "7611140992000044"}           
           //,{ "04322222162980", "7611140993000024"}
           //crf
           //,{ "04063CEAA53080", "7111140983000038"}
           //,{ "040659EAA53080", "7111140988000005"}
           //,{ "04427122EB3580", "7511130995000088"}
           //,{ "04032B4AFA3680", "7111140988000005"}   
           //,{ "04608CCA3D2480", "0417149985000016"}
           // AL 
           ,{ "047A334A3C3480", "6817159988000024"}
           ,{ "04874C5AEB3680", "0817159987000181"}
           ,{ "046F9222EB2F80", "7313150028000302"}
           ,{ "046C22FAEF3880", "7313150024000301"}
           ,{ "04333282583B80", "7413149988000026"}
           ,{ "04618CC23D2480", "7211130986000010"}
           ,{ "04708CC23D2480", "7416140995000007"}
           // 8K
           ,{ "043644428B3380", "7416140995000007"}
           ,{ "045344428B3380", "7211130986000010"}
           ,{ "049444428B3380", "7313150024000301"}
           ,{ "043444428B3380", "7413149988000026"}
        }; 
        private ISymCryptor tDesCryptor = null;

        [SetUp]
        public void InitContext()
        {
            //  add card map list
            XElement xe = null;
            xe = XElement.Load(@"CardMapList.xml");
            // get CARD LIST
            XElement cards = xe.XPathSelectElement("//CARDS");
            //log.Debug(cards);
            // 走訪各 <CARD> 屬性
            foreach (XElement card in cards.Elements("CARD"))
            {
                string uid = card.Attribute( "uid" ).Value;
                string cid = card.Attribute( "cid" ).Value;
                //foreach (XAttribute xa in card.Attributes())
                //{
                //    //log.Debug(xa.Name + ":" + xa.Value);
                //    if( "uid" == xa.Name )
                //    {
                //        uid = xa.Value;
                //    }
                //    else if( "cid" == xa.Name )
                //    {
                //        cid = xa.Value;
                //    }
                //}
                this.dicCardMap[uid] = cid;
            }
            //
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
                     ||  atrHex.StartsWith( "3B8F8001804F" )
                    )
                    {
                        log.Debug("Got MifareDesfire EV1 card in [" + reader + "]");
                        APDUResponse response = this.icash2Player.ProcessSequence("GetVersion");  
                        if (response.SW1 == 0x91 && response.SW2 == 0x00)
                        {
                            this.uid = this.byteWorker.SubArray(response.Data, 0, 7);
                            log.Debug( m => m( "Get UID:[{0}]", this.hexConverter.Bytes2Hex( this.uid ) ) );
                            chkOK = true;
                            break;
                        }
                        else
                        {
                            log.Debug(m => m("Get UID fail: {0:X2}{1:X2}...", response.SW1, response.SW2));
                        }
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
        public void Test00ResetCMKSettings()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            response = this.icash2Player.ProcessSequence("SelectPICC", sp);
            //
            byte[] sesKey = this.doAuth("seedKeyCMKHex");
            //byte[] sesKey = this.doAuth("origCMK0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.symCryptor.SetKey(sesKey);
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            //
            byte[] cmd = new byte[] { 0x54 };
            byte[] keySet = new byte[] { 0x0F };
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(this.byteWorker.Combine(cmd, keySet));
            byte[] rawData = this.byteWorker.Combine(keySet, crc32);
            // raw data with zero paddings 
            rawData = this.byteWorker.Combine(rawData, this.byteWorker.Fill(16 - rawData.Length % 16, 0x00));
            log.Debug("raw data:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
            //
            byte[] encData = this.symCryptor.Encrypt(rawData);
            // get last 16 bytes as iv 
            iv = this.byteWorker.SubArray(encData, encData.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encData));
            //
            response = this.icash2Player.ProcessSequence("ChangeKeySettings", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // update iv
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // check if cmac ok
            // get first 8 bytes of iv            
            byte[] cmac = byteWorker.SubArray(iv, 0, 8);
            log.Debug("cmac:[" + this.hexConverter.Bytes2Hex(cmac) + "]");
            Assert.AreEqual(this.byteWorker.SubArray(response.Data, 0, 8), cmac);
        }
               
        [Test]
        public void Test01FormatPICCWithOrigMaster()
        {
            // 2key, 3Des
            log.Debug("Authenticate(3)DES with Default Card Master Key ...");
            byte[] sesKey = this.authOrigCMK();
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            APDUResponse response = null;
            response = this.icash2Player.ProcessSequence("FormatPICC");
            log.Debug(response);
        }

        //[Test]
        public void Test01FormatPICCWithAesAllZero()
        {
            //           
            byte[] sesKey = this.doAuth("origCMK0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            byte[] iv = this.byteWorker.Fill(16, 0x00);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.SetMacKey(sesKey);
            byte[] cmac = null;
            this.cMacWorker.DataInput(new byte[] { 0xFC });
            cmac = this.cMacWorker.GetMac();
            iv = cmac;
            //
            APDUResponse response = null;
            response = this.icash2Player.ProcessSequence("FormatPICC");
            log.Debug(response);
            //
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            cmac = this.cMacWorker.GetMac();
            log.Debug("Calc CMAC:[" + this.hexConverter.Bytes2Hex(cmac) + "]");
            Assert.AreEqual(this.byteWorker.SubArray(cmac, 0, 8), response.Data);
        }

        //[Test]
        public void Test01FormatPICCWithIcash2CMK()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            response = this.icash2Player.ProcessSequence("SelectPICC", sp);
            //
            byte[] sesKey = this.doAuth("seedKeyCMKHex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            byte[] iv = SymCryptor.ConstZero;
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.SetMacKey(sesKey);
            byte[] cmac = null;            
            //
            response = this.icash2Player.ProcessSequence("FormatPICC");
            log.Debug(response);
            //
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            cmac = this.cMacWorker.GetMac();
            log.Debug("Calc CMAC:[" + this.hexConverter.Bytes2Hex(cmac) + "]");
            Assert.AreEqual(this.byteWorker.SubArray(cmac, 0, 8), response.Data);
        }

        [Test]
        public void Test02CreateApplication()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //   
            string aid = "118716";
            string keySet1 = "0F";
            string keySet2 = "8E";    //AES:MSB 0b10, LSB:0b1110,Max 14 keys            
            response = this.icash2Player.ProcessSequence("SelectPICC");
            log.Debug(response);
            //
            log.Debug( m => m( "Create Application:[{0}]", aid ) );
            sp.Clear();
            sp.Add("MSG", aid + keySet1 + keySet2);
            response = this.icash2Player.ProcessSequence("CreateApplication", sp);
            log.Debug(response);
        }

        [Test]
        public void Test99DeleteApplication()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            string aid = "118716";
            log.Debug("Delete Application:[" + aid + "]");
            //
            // must auth with picc master key 1st.            
            log.Debug("Delete Application....");
            sp.Clear();
            sp.Add( "MSG", aid );
            response = this.icash2Player.ProcessSequence("DeleteApplication", sp);
            log.Debug(response);
        }

        [Test]
        public void Test03CreateFiles()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            string aid = "118716";
            sp.Add("AID", aid);
            response = this.icash2Player.ProcessSequence("SelectAID", sp);

            foreach (string fNR in dicFNR.Keys)
            {

                string fileType = dicFNR[fNR].Substring(0, 2);
                string data = fNR + "00EEEE" + dicFNR[fNR].Substring(8);

                sp.Clear();
                sp.Add("MSG", data);
                if ("00".Equals(fileType))
                {
                    response = this.icash2Player.ProcessSequence("CreateStdDataFile", sp);
                    Assert.AreEqual(0x00, response.SW2);
                }
                else if ("01".Equals(fileType))
                {
                    response = this.icash2Player.ProcessSequence("CreateBackupDataFile", sp);
                    Assert.AreEqual(0x00, response.SW2);
                }
                else if ("02".Equals(fileType))
                {
                    response = this.icash2Player.ProcessSequence("CreateValueFile", sp);
                    Assert.AreEqual(0x00, response.SW2);
                }
                else if ("04".Equals(fileType))
                {
                    response = this.icash2Player.ProcessSequence("CreateCyclicRecordFile", sp);
                    Assert.AreEqual(0x00, response.SW2);
                }
            }
        }

        [Test]
        public void Test04FillData()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            string date = this.dateUtility.GetStrToday();
            string cid;
            log.Debug(this.uid);
            Assert.True(this.dicCardMap.TryGetValue(this.hexConverter.Bytes2Hex(this.uid), out cid));
            //
            string fmtVer = "0002";
            string aid = "118716";
            sp.Add("AID", aid);
            response = this.icash2Player.ProcessSequence("SelectAID", sp);
            //
            log.Debug("WriteData with FNR 01...");
            sp.Clear();
            // fileNo(1) || offset(3) || length(3) || rawData(4)
            string msg = "01" + "000000" + "040000" + date;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 02...");
            sp.Clear();
            
            msg = "02" + "000000" + "0F0000" + date 
                + cid.Substring(2, 2)
                //+ "17"  // auto load card
                + fmtVer + cid;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 03...");
            sp.Clear();
            msg = "03" + "000000" + "080000" + cid;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 04...");
            sp.Clear();
            msg = "04" + "000000" + "280000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(36, 0x20))
                + "00000000";
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 05...");
            sp.Clear();
            msg = "05" + "000000" + "090000"; // startDate(4) || endDate(4) || cardStatus(1) , cardStatus:0x01 -> enable
            if( "17".Equals(cid.Substring(2, 2) ))
            {
                string startDate = null;
                this.dateUtility.TryGetDiffYearStr( this.dateUtility.GetStrToday(), 5, out startDate );
                this.dateUtility.TryGetDiffMonthStr(startDate, 1, out startDate);
                this.dateUtility.TryGetDiffDateStr(startDate.Substring(0, 6) + "01", -1, out startDate);
                log.Debug( "Expire date1:[" + startDate + "]" );
                msg += (  startDate.Substring( 0, 8 ) + "00000000" + "01" );
            }
            else
            {
                msg += ( this.hexConverter.Bytes2Hex(this.byteWorker.Fill(8, 0x00)) + "01" );
            }
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 0C...");
            sp.Clear();
            msg = "0C" + "000000" + "040000" + "00010000";
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 0E...");
            sp.Clear();
            msg = "0E" + "000000" + "040000" + "00000000";
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 0F...");
            sp.Clear();
            msg = "0F" + "000000" + "020000" + "0000";
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 10...");
            sp.Clear();
            msg = "10" + "000000" + "330000"
              + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(19, 0x00))
              + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(19, 0x20))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(13, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 11...");
            sp.Clear();
            msg = "11" + "000000" + "600000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(49, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 12...");
            sp.Clear();
            // APDU max length: 60, APDU(6) = CLA(1)||INS(1)||P1(1)||P2(1)||LC(1)||LE(1), left 54
            msg = "12" + "000000" + "600000" // 7
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00)) // 47
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(49, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 13...");
            sp.Clear();
            msg = "13" + "000000" + "100000";
            if( "7413149988000026".Equals(cid) )
            {
                
                //不給點common area offset 12 改為 0x01
                msg +=
                (
                   this.hexConverter.Bytes2Hex(this.byteWorker.Fill(12, 0x00))
                 + "01"
                 + "000000"
                );
            }
            else if( "17" != cid.Substring(2,2) )
            { 
                 msg += this.hexConverter.Bytes2Hex(  this.byteWorker.Fill(16, 0x00) );
            }
            else // autoload card
            {
                msg += 
                (
                    "10"  // Autoload flag on, offline flag off
                  + "F401" // autoload NT.500 per time
                  + "1027" // max amount 10000
                  + "1027"  // max deduct 10000
                  + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(9, 0x00))
                );
            }
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 14...");
            sp.Clear();
            msg = "14" + "000000" + "010000" + "00";
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 15...");
            sp.Clear();
            msg = "15" + "000000" + "600000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(49, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 16...");
            sp.Clear();
            msg = "16" + "000000" + "600000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(49, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 17...");
            sp.Clear();
            msg = "17" + "000000" + "360000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(7, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 18...");
            sp.Clear();
            msg = "18" + "000000" + "360000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(7, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 19...");
            sp.Clear();
            msg = "19" + "000000" + "360000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(7, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 1A...");
            sp.Clear();
            msg = "1A" + "000000" + "360000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(7, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            log.Debug("WriteData with FNR 1B...");
            sp.Clear();
            msg = "1B" + "000000" + "100000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(16, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0x00, response.SW2);
            //            
            log.Debug("WriteData with FNR 1D...");
            sp.Clear();
            msg = "1D" + "000000" + "600000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(49, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //            
            log.Debug("WriteData with FNR 1E...");
            sp.Clear();
            msg = "1E" + "000000" + "600000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(49, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            //
            //            
            log.Debug("WriteData with FNR 1F...");
            sp.Clear();
            // APDU max length: 60
            msg = "1F" + "000000" + "600000"
                + this.hexConverter.Bytes2Hex(this.byteWorker.Fill(47, 0x00))
            ;
            sp.Clear();
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("WriteData", sp);
            log.Debug(response);
            Assert.AreEqual(0xAF, response.SW2);
            //
            sp.Clear();
            msg = this.hexConverter.Bytes2Hex(this.byteWorker.Fill(49, 0x00));
            sp.Add("MSG", msg);
            response = this.icash2Player.ProcessSequence("ContinueWithData", sp);
            Assert.AreEqual(0x00, response.SW2);
            // Commit all!
            sp.Clear();
            response = this.icash2Player.ProcessCommand("CommitTransaction");
            Assert.AreEqual(0x00, response.SW2);
        }

        [Test]
        public void Test05ChangeFileSettings()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            string aid = "118716";
            sp.Add("AID", aid);
            response = this.icash2Player.ProcessSequence("SelectAID", sp);

            foreach (string fNR in dicFNR.Keys)
            {
                string data = fNR + dicFNR[fNR].Substring(2, 6);

                sp.Clear();
                sp.Add("MSG", data);
                response = this.icash2Player.ProcessSequence("ChangeFileSettings", sp);
                Assert.AreEqual(0x00, response.SW2);
            }
        }

        /// <summary>
        ///  Must check before change AMK Settings
        /// </summary>
        [Test]
        public void Test05ValidFileSettings()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            string aid = "118716";
            sp.Add("AID", aid);
            response = this.icash2Player.ProcessSequence("SelectAID", sp);

            foreach (string fNR in this.dicFNR.Keys)
            {
                sp.Clear();
                sp.Add("FNR", fNR);
                response = this.icash2Player.ProcessSequence("GetFileSettings", sp);
                byte[] resData = response.Data;
                if (0x04 == resData[0])
                {
                    // skip current number of records(3)
                    resData = this.byteWorker.SubArray(resData, 0, resData.Length - 3);
                }
                Assert.AreEqual(this.dicFNR[fNR], this.hexConverter.Bytes2Hex(resData));
            }
        }

        [Test]
        public void Test06ChangAPKeys()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            IList<string> listKey = new List<string>()
            {
                 "seedKey1Hex"
                ,"seedKey2Hex"
                ,"seedKey3Hex"
                ,"seedKey8Hex"
                ,"seedKey9Hex"
                ,"seedKeyAHex"
                ,"seedKeyBHex"
                ,"seedKeyCHex"
               // ,"seedKey0Hex"
            };
            //string keyName = null;
            byte[] divKey = null;
            byte[] iv = this.byteWorker.Fill(16, 0x00);
            byte[] defaultKey = this.byteWorker.Fill(16, 0x00);
            //
            byte[] sesKey = this.doAuth("origAMK0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            this.symCryptor.SetKey(sesKey);
            //
            foreach (string keyName in listKey)
            {
                this.symCryptor.SetIv(iv);
                divKey = this.getDivKey(keyName);
                log.Debug(keyName.Substring(4) + ":[" + this.hexConverter.Bytes2Hex(divKey) + "]");
                byte[] cmd = new byte[] { 0xC4 };
                byte[] kNr = this.hexConverter.Hex2Bytes("0" + keyName.Substring(7, 1));
                byte[] keyVer = new byte[] { 0x00 };
                byte[] keyXor = this.byteWorker.ExclusiveOr(defaultKey, divKey);
                byte[] crcData = this.byteWorker.Combine(cmd, kNr, keyXor, keyVer);
                log.Debug("crcData:[" + this.hexConverter.Bytes2Hex(crcData) + "]");
                byte[] crcKeyXor = this.nxpCrc32Worker.ComputeChecksumBytes
                (
                    this.byteWorker.Combine(cmd, kNr, keyXor, keyVer)
                );
                byte[] crcDivKey = this.nxpCrc32Worker.ComputeChecksumBytes(divKey);
                byte[] rawData = this.byteWorker.Combine
                (
                    this.byteWorker.Combine
                    (
                        keyXor, keyVer, crcKeyXor, crcDivKey
                    , this.byteWorker.Fill(7, 0x00)
                    )
                );
                log.Debug("rawData:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
                // KeyXor(16) || KeyVer(1) || crcKeyXor(4) || crcDivKey(4) || Zero Padding(7)
                byte[] encData = this.symCryptor.Encrypt(rawData);
                log.Debug("encData:[" + this.hexConverter.Bytes2Hex(encData) + "]");
                // updata iv
                iv = this.byteWorker.SubArray(encData, encData.Length - 16, 16);
                log.Debug("nexe iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
                //                
                byte[] msg = this.byteWorker.Combine(kNr, encData);
                sp.Clear();
                sp.Add("MSG", this.hexConverter.Bytes2Hex(msg));
                sp.Add("LEN", this.hexConverter.Byte2Hex((byte)(msg.Length)));
                response = this.icash2Player.ProcessSequence("ChangeKey", sp);
                log.Debug(response);
                if (response.SW1 == 0x91 && response.SW2 == 0x00)
                {
                    log.Debug("data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
                }
                // check CMAC
                byte[] cmacData = new byte[] { response.SW2 };
                this.cMacWorker.SetIv(iv);
                this.cMacWorker.SetMacKey(sesKey);
                this.cMacWorker.DataInput(cmacData);
                byte[] cmac = this.cMacWorker.GetMac();
                log.Debug(this.hexConverter.Bytes2Hex(cmac));
                Assert.AreEqual(this.byteWorker.SubArray(cmac, 0, 8), response.Data);
                //
                iv = cmac;
                log.Debug("nexe iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            }
        }

        [Test]
        public void Test07ChangAMK()
        {
            // K1 == K2
            string keyName = null;
            byte[] divKey = null;
            byte[] iv = this.byteWorker.Fill(16, 0x00);
            byte[] defaultKey = this.byteWorker.Fill(16, 0x00);
            //
            byte[] sesKey = this.doAuth("origAMK0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            this.symCryptor.SetIv(iv);
            this.symCryptor.SetKey(sesKey);
            //
            keyName = "seedKey0Hex";
            divKey = this.getDivKey(keyName);
            byte[] cmd = new byte[] { 0xC4 };
            byte[] kNr = this.hexConverter.Hex2Bytes("0" + keyName.Substring(7, 1));
            byte[] keyVer = new byte[] { 0x00 };
            byte[] crcData = this.byteWorker.Combine(cmd, kNr, divKey, keyVer);
            log.Debug("crcData:[" + this.hexConverter.Bytes2Hex(crcData) + "]");
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            byte[] rawData = this.byteWorker.Combine
            (
                this.byteWorker.Combine
                (
                    divKey, keyVer, crc32
                   , this.byteWorker.Fill(11, 0x00)
                )
            );
            log.Debug("rawData:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
            // divKey(16) || KeyVer(1) || crc32(4) || Zero Padding(11)
            byte[] encData = this.symCryptor.Encrypt(rawData);
            // updata iv, useless
            iv = this.byteWorker.SubArray(encData, encData.Length - 16, 16);
            //
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            byte[] msg = this.byteWorker.Combine(kNr, encData);
            sp.Add("MSG", this.hexConverter.Bytes2Hex(msg));
            sp.Add("LEN", this.hexConverter.Byte2Hex((byte)(msg.Length)));
            response = this.icash2Player.ProcessSequence("ChangeKey", sp);
            log.Debug(response);
            // no cmac return
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Change AMK OK!");
            }
            Assert.AreEqual(0x00, response.SW2);
        }

        [Test]
        public void Test08ChangeAMKSettings()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            sp.Clear();
            sp.Add("AID", "118716");
            response = this.icash2Player.ProcessSequence("SelectAID", sp);
            log.Debug(response);
            //
            byte[] sesKey = this.doAuth("seedKey0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.symCryptor.SetKey(sesKey);
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            //
            byte[] cmd = new byte[] { 0x54 };
            byte[] keySet = new byte[] { 0x09 };//new byte[] { 0x09, 0x8E };
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(this.byteWorker.Combine(cmd, keySet));
            byte[] rawData = this.byteWorker.Combine(keySet, crc32);
            // raw data with zero paddings 
            rawData = this.byteWorker.Combine(rawData, this.byteWorker.Fill(16 - rawData.Length % 16, 0x00));
            log.Debug("raw data:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
            //
            byte[] encData = this.symCryptor.Encrypt(rawData);
            // get last 16 bytes as iv 
            iv = this.byteWorker.SubArray(encData, encData.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encData));
            //
            response = this.icash2Player.ProcessSequence("ChangeKeySettings", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // update iv
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // check if cmac ok
            // get first 8 bytes of iv            
            byte[] cmac = byteWorker.SubArray(iv, 0, 8);
            log.Debug("cmac:[" + this.hexConverter.Bytes2Hex(cmac) + "]");
            Assert.AreEqual(this.byteWorker.SubArray(response.Data, 0, 8), cmac);
            // get all apdu logs
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void Test07ValidNewApKeys()
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

        //[Test]
        public void Test09ChangDefaultCMK2AESAllZero()
        {
            // New CMK Key
            byte[] newCMK = this.hexConverter.Hex2Bytes(this.dicKey["origCMK0Hex"]);
            byte[] newKeyVersion = new byte[] { 0x00 };
            byte[] crc16 = this.nxpCrc16Worker.ComputeChecksumBytes
            (
                this.byteWorker.Combine(newCMK, newKeyVersion)
            );
            string expectCrc =
                "7545";
            log.Debug("CRC16:[" + this.hexConverter.Bytes2Hex(crc16) + "]");
            Assert.AreEqual(expectCrc, this.hexConverter.Bytes2Hex(crc16));
            //
            byte[] rawData = this.byteWorker.Combine(newCMK, newKeyVersion, crc16);
            // multiple of 8
            if (rawData.Length % 8 != 0)
            {
                rawData = this.byteWorker.Combine(rawData, this.byteWorker.Fill(8 - rawData.Length % 8, 0x00));
            }
            // 2key, 3Des
            log.Debug("Authenticate(3)DES with Default Card Master Key ...");
            byte[] sesKey = this.authOrigCMK();
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.tDesCryptor.SetKey(sesKey);
            this.tDesCryptor.SetIv(this.byteWorker.Fill(8, 0x00));
            byte[] encData = this.tDesCryptor.Encrypt(rawData);
            //
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            byte[] msg = this.byteWorker.Combine(new byte[] { 0x80 }, encData);
            sp.Add("MSG", this.hexConverter.Bytes2Hex(msg));
            sp.Add("LEN", this.hexConverter.Byte2Hex((byte)(msg.Length)));
            response = this.icash2Player.ProcessSequence("ChangeKey", sp);
            log.Debug(response);
        }

        [Test]
        public void Test09ChangDefaultCMK2Icash2()
        {
            // New CMK Key
            byte[] newCMK = this.getDivKey("seedKeyCMKHex");
            byte[] newKeyVersion = new byte[] { 0x00 };
            byte[] crc16 = this.nxpCrc16Worker.ComputeChecksumBytes
            (
                this.byteWorker.Combine(newCMK, newKeyVersion)
            );
            log.Debug("CRC16:[" + this.hexConverter.Bytes2Hex(crc16) + "]");
            //
            byte[] rawData = this.byteWorker.Combine(newCMK, newKeyVersion, crc16);
            // multiple of 8
            if (rawData.Length % 8 != 0)
            {
                rawData = this.byteWorker.Combine(rawData, this.byteWorker.Fill(8 - rawData.Length % 8, 0x00));
            }
            log.Debug("rawData:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
            // 2key, 3Des
            log.Debug("Authenticate(3)DES with Default Card Master Key ...");
            byte[] sesKey = this.authOrigCMK();
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.tDesCryptor.SetKey(sesKey);
            this.tDesCryptor.SetIv(this.byteWorker.Fill(8, 0x00));
            byte[] encData = this.tDesCryptor.Encrypt(rawData);
            //
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            byte[] msg = this.byteWorker.Combine(new byte[] { 0x80 }, encData);
            sp.Add("MSG", this.hexConverter.Bytes2Hex(msg));
            sp.Add("LEN", this.hexConverter.Byte2Hex((byte)(msg.Length)));
            response = this.icash2Player.ProcessSequence("ChangeKey", sp);
            log.Debug(response);
        }

        //[Test]
        public void Test00RestoreCMKFromAESAllZero()
        {
            // Current CMK, AES All Zero 
            // Restore to Default CMK Key,TDES 2Key All zero
            byte[] kNr = new byte[] { 0x00 };
            byte[] newCMK = this.hexConverter.Hex2Bytes(this.dicKey["origCMK0Hex"]);
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes
            (
                //this.byteWorker.Combine( new byte[] { 0xC4, 0x80 }, newCMK, new byte[] { 0x00 } )
                // MSB 2 bits: 00 -> DES/TDES 2 Key
                this.byteWorker.Combine(new byte[] { 0xC4 }, kNr, newCMK)
            );
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            byte[] rawData = this.byteWorker.Combine(newCMK, crc32);
            // padding 0x00, multiple of 16
            if (rawData.Length % 16 != 0)
            {
                rawData = this.byteWorker.Combine(
                    rawData, this.byteWorker.Fill(16 - rawData.Length % 16, 0x00)
                );
            }
            // AES128,AllZero
            byte[] sesKey = this.doAuth("origCMK0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.symCryptor.SetKey(sesKey);
            this.symCryptor.SetIv(this.byteWorker.Fill(16, 0x00));
            byte[] encData = this.symCryptor.Encrypt(rawData);
            //
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            byte[] msg = this.byteWorker.Combine(kNr, encData);
            sp.Add("MSG", this.hexConverter.Bytes2Hex(msg));
            sp.Add("LEN", this.hexConverter.Byte2Hex((byte)(msg.Length)));
            response = this.icash2Player.ProcessSequence("ChangeKey", sp);
            log.Debug(response);
        }

        [Test]
        public void Test00RestorCMKFromAESIcash2()
        {
            // Current CMK, AES icash2 
            // Restore to Default CMK Key,TDES 2Key All zero
            byte[] cmd = new byte[] { 0xC4 };
            // MSB 2 bits: 00 -> DES/TDES 2 Key
            byte[] kNr = new byte[] { 0x00 };
            byte[] newCMK = this.hexConverter.Hex2Bytes(this.dicKey["origCMK0Hex"]);
            byte[] crcData = this.byteWorker.Combine(cmd, kNr, newCMK);
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("crcData:[" + this.hexConverter.Bytes2Hex(crcData) + "]");
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            byte[] rawData = this.byteWorker.Combine(newCMK, crc32);
            // padding 0x00, multiple of 16
            if (rawData.Length % 16 != 0)
            {
                rawData = this.byteWorker.Combine
                (
                    rawData, this.byteWorker.Fill(16 - rawData.Length % 16, 0x00)
                );
            }
            log.Debug("rawData:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
            // AES128,div to icash2
            byte[] sesKey = this.doAuth("seedKeyCMKHex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.symCryptor.SetKey(sesKey);
            this.symCryptor.SetIv(SymCryptor.ConstZero);
            byte[] encData = this.symCryptor.Encrypt(rawData);
            log.Debug("encData:[" + this.hexConverter.Bytes2Hex(encData) + "]");
            //
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            byte[] msg = this.byteWorker.Combine(kNr, encData);
            sp.Add("MSG", this.hexConverter.Bytes2Hex(msg));
            response = this.icash2Player.ProcessSequence("ChangeKey", sp);
            log.Debug(response);
        }

        //[Test]
        public void Test18AuthNewCMKAesAllZero()
        {
            // AES128,AllZero
            byte[] sesKey = this.doAuth("origCMK0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
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

        [Test]
        public void Test11GetFileSettings()
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
                log.Debug("FNR:[" + fNR + "]: " + this.hexConverter.Bytes2Hex(fSet));
            }
        }

        [Test]
        public void Test00ValidDefaultCMK()
        {
            // 2key, 3Des
            log.Debug("Authenticate(3)DES with Default Card Master Key ...");
            byte[] sesKey = this.authOrigCMK();
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
        }

        [Test]
        public void Test09ValidIcash2CMK()
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

        //[Test]
        public void TestCMac()
        {
            this.symCryptor = this.ctx["aesCryptor"] as SymCryptor;
            this.symCryptor.SetKey(this.hexConverter.Hex2Bytes("56698645E5062BCB7966F042932E3D7F"));
            this.symCryptor.SetIv(this.hexConverter.Hex2Bytes("21885311B15CD46AFEC71C16C4AE37D9"));
            byte[] decrypted = this.byteWorker.Combine
            (
                new byte[] { 0x00, 0x80 }
               , this.byteWorker.Fill(14, 0x00)
            );
            byte[] result = this.symCryptor.Encrypt(decrypted);
            log.Debug(this.hexConverter.Bytes2Hex(result));
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


        //[Test]
        public void Test97AuthOrigAMK()
        {
            byte[] sesKey = this.doAuth("origAMK0Hex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
        }

        [Test]
        public void Test10ChangeCMKSettings()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            //
            response = this.icash2Player.ProcessSequence("SelectPICC", sp);
            //
            byte[] sesKey = this.doAuth("seedKeyCMKHex");
            log.Debug("SessionKey:[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            this.symCryptor.SetKey(sesKey);
            byte[] iv = SymCryptor.ConstZero;
            this.symCryptor.SetIv(iv);
            //
            byte[] cmd = new byte[] { 0x54 };
            // Change Card Setting to 0x09
            byte[] keySet = new byte[] { 0x09 };
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(this.byteWorker.Combine(cmd, keySet));
            byte[] rawData = this.byteWorker.Combine(keySet, crc32);
            // raw data with zero paddings 
            rawData = this.byteWorker.Combine(rawData, this.byteWorker.Fill(16 - rawData.Length % 16, 0x00));
            log.Debug("raw data:[" + this.hexConverter.Bytes2Hex(rawData) + "]");
            //
            byte[] encData = this.symCryptor.Encrypt(rawData);
            // get last 16 bytes as iv 
            iv = this.byteWorker.SubArray(encData, encData.Length - 16, 16);
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            //
            sp.Clear();
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encData));
            //
            response = this.icash2Player.ProcessSequence("ChangeKeySettings", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            // update iv
            this.cMacWorker.SetMacKey(sesKey);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.DataInput(new byte[] { response.SW2 });
            iv = this.cMacWorker.GetMac();
            log.Debug("next iv:[" + this.hexConverter.Bytes2Hex(iv) + "]");
            // check if cmac ok
            // get first 8 bytes of iv            
            byte[] cmac = byteWorker.SubArray(iv, 0, 8);
            log.Debug("cmac:[" + this.hexConverter.Bytes2Hex(cmac) + "]");
            Assert.AreEqual(this.byteWorker.SubArray(response.Data, 0, 8), cmac);
        }

        [Test]
        public void Test10ValidCMKSettings()
        {
            string expected = "0901";
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
        
        //[Test]
        public void Test99FillDataWithFullEncryption()
        {
            SequenceParameter sp = new SequenceParameter();
            APDUResponse response = null;
            string date = this.dateUtility.GetStrToday();
            //
            string aid = "118716";
            sp.Add("AID", aid);
            response = this.icash2Player.ProcessSequence("SelectAID", sp);
            //
            string keyName = "seedKey1Hex";
            log.Debug("Auth key:[" + keyName.Substring(7, 1) + "]...");
            byte[] sesKey = this.doAuth(keyName);
            log.Debug("Session" + keyName.Substring(4, 4) + ":[" + this.hexConverter.Bytes2Hex(sesKey) + "]");
            //
            log.Debug("WriteData with FNR 01...");
            sp.Clear();
            byte[] rawData = this.hexConverter.Hex2Bytes(date);
            byte[] crcData = this.byteWorker.Combine
            (
                // cmd(1) || fileNo(1) || offset(3) || length(3) || rawData(4)
                this.hexConverter.Hex2Bytes
                (
                    "3D" + "01" + "000000" + "040000"
                )
                , rawData

            );
            byte[] crc32 = this.nxpCrc32Worker.ComputeChecksumBytes(crcData);
            log.Debug("CRC32:[" + this.hexConverter.Bytes2Hex(crc32) + "]");
            //           
            byte[] decryptedMsg = this.byteWorker.Combine
            (
                 rawData  // (4)
               , crc32    // (4)
                //, this.byteWorker.Fill(8, 0x00)
            );
            decryptedMsg = this.byteWorker.Combine
            (
                decryptedMsg, this.byteWorker.Fill(16 - decryptedMsg.Length % 16, 0x00)
            );
            log.Debug("DataCrc32Padding:[" + this.hexConverter.Bytes2Hex(decryptedMsg) + "]");

            // current iv, reset to all zero after auth
            byte[] iv = SymCryptor.ConstZero;
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
            sp.Add("MSG", "01" + "000000" + "040000" + this.hexConverter.Bytes2Hex(encryptedMsg));
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
        }

        //[Test]
        public void Test99Negative()
        {
            int neg = -65;
            string negStr = "FFFFFFBF";
            byte[] resBytes = BitConverter.GetBytes(neg);
            log.Debug(this.hexConverter.Bytes2Hex(resBytes));
            Assert.AreEqual(negStr, this.hexConverter.Bytes2Hex(this.byteWorker.Reverse(resBytes)));

            byte[] negBytes = this.byteWorker.Reverse(this.hexConverter.Hex2Bytes(negStr));
            int result = BitConverter.ToInt32(negBytes, 0);
            log.Debug(result);
            Assert.AreEqual(neg, result);
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
            this.symCryptor = ctx["aesCryptor"] as ISymCryptor;
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
