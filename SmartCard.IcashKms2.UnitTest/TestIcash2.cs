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
//using SmartCard.ContactIcash;
using Kms.Crypto;

namespace SmartCard.Player.UnitTest
{
    [TestFixture]
    public class TestIcash2
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestIcash2));
        //
        IApplicationContext ctx;
        ICard cardNative;
        APDUPlayer icash2Player = null; 
        IHexConverter hexConverter = null;
        IByteWorker byteWorker = null;
       
        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.icash2Player = ctx["apduPlayer"] as APDUPlayer;                       
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            // Contactless use single connection  
            this.cardNative = this.icash2Player.CardNative;
            //            
            this.icash2Player.LoadCommandFile("Icash2CmdList.xml");            
            //
            string[] readers = this.cardNative.ListReaders();
            if(readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            // find first MifareDesfire EV1 card
            foreach(string reader in readers)
            {
                log.Debug("Connect: [" + reader + "]....");
                try
                {
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
                        string uid = this.hexConverter.Bytes2Hex(response.Data);
                        log.Debug("Got icash2 uid:[" + uid + "]");
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
        }

        [Test]
        public void TestGetVersion()
        {          
            //this.icash2Player.CardNative.Connect( 
            log.Debug("Get Version...");
            APDUResponse response = this.icash2Player.ProcessSequence("GetVersion");
            log.Debug(response);            
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("UID:[" + this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, 0, 7)) + "]");
            }
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestGetAID()
        {
            log.Debug("Get AIDs...");
            APDUResponse response = this.icash2Player.ProcessSequence("GetAIDS");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("AID:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            SequenceParameter sp = new SequenceParameter();
            sp.Add("AID", "118716");
            response = this.icash2Player.ProcessSequence("SelectAID", sp);
            log.Debug(response);
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestGetCID()
        {
            log.Debug("Get CID...");
            APDUResponse response = this.icash2Player.ProcessSequence("GetCID");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("CID:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }            
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
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

       // [Test]
        public void Test01CreateApplication()
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("MSG", "1122330F8E");
            log.Debug("Create Application 112233...");
            APDUResponse response = this.icash2Player.ProcessSequence("CreateApplication", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Success...");
            }
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

       // [Test]
        public void Test02DeleteApplication()
        {
            SequenceParameter sp = new SequenceParameter();
            sp.Add("MSG", "112233");
            log.Debug("Delete Application...");
            APDUResponse response = this.icash2Player.ProcessSequence("DeleteApplication", sp );
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Success...");
            }
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestGetKeyVersion()
        {
            log.Debug("Get Key Version...");            
            APDUResponse response = this.icash2Player.ProcessSequence("GetKeyVersion");
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestGetKeySettings()
        {
            log.Debug("Get Key Settings...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("AID", "000000");
            APDUResponse response = this.icash2Player.ProcessSequence("GetKeySettings", sp);
            log.Debug(response);
            if (response.SW1 == 0x91 && response.SW2 == 0x00)
            {
                log.Debug("Data:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
            }
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestGetVersionNative()
        {            
            //this.cardNative.Connect(readerName, SHARE.Shared, PROTOCOL.T0orT1);

            APDUCommand cmd = new APDUCommand
            (
                0x90
              , 0x60
              , 0x00
              , 0x00
              , null
              , new byte[] { 0x00 }
            );
            log.Debug(cmd);

            APDUResponse response = this.cardNative.Transmit(cmd);

            log.Debug(response);
            while (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {
                cmd = new APDUCommand
                (
                    0x90
                  , 0xAF
                  , 0x00
                  , 0x00
                  , null
                  , new byte[] { 0x00 }
                );
                log.Debug(cmd);

                response = this.cardNative.Transmit(cmd);

                log.Debug(response);
                if (response.SW1 == 0x91 && response.SW2 == 0x00)
                {
                    log.Debug("UID:[" + this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, 0, 7)) + "]");
                }
            }
            // disconnect...
            //this.cardNative.Disconnect(DISCONNECT.Unpower);
        }

        [Test]
        public void TestReadRecords()
        {
            log.Debug("Read Records...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add("MSG", "0D000000000000");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadRecords", sp );
            log.Debug(response);
            byte[] txRecs = response.Data;
            while (response.SW1 == 0x91 && response.SW2 == 0xAF)
            {               
                response = this.icash2Player.ProcessCommand("Continue");
                log.Debug("response:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
                txRecs = this.byteWorker.Combine(txRecs, response.Data);
            }
            //
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
            //
            int recSize = 51;
            int cnt = txRecs.Length / recSize;
            CTxRec[] cTxRecs = new CTxRec[cnt];

            for (int i = 0; i < cnt; i++)
            {
                byte[] rec = this.byteWorker.SubArray(txRecs, i * recSize, recSize);
                CTxRec cTxRec = new CTxRec();
                cTxRec.TxRecHex = this.hexConverter.Bytes2Hex(rec);

                int p = 0;
                cTxRec.CardTxSn = BitConverter.ToUInt32
                (
                    this.byteWorker.Reverse
                    (
                        this.byteWorker.SubArray(rec, p, 4)
                    ), 0
                );
                p += 4;
                cTxRec.TxDateTime = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 7));
                p += 7;
                cTxRec.TId = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 8));
                p += 8;
                cTxRec.RwId = Encoding.ASCII.GetString(this.byteWorker.SubArray(rec, p, 19));
                p += 19;
                cTxRec.TxType = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 1));
                p += 1;
                cTxRec.CardPLSn = BitConverter.ToUInt32
                (
                    this.byteWorker.Reverse
                    (
                        this.byteWorker.SubArray(rec, p, 4)
                    ), 0
                );
                p += 4;
                cTxRec.TxAmount = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 4));
                p += 4;
                cTxRec.Balance = BitConverter.ToInt32
                (
                    this.byteWorker.Reverse
                    (
                        this.byteWorker.SubArray(rec, p, 4)
                    ), 0
                );
                cTxRecs[i] = cTxRec;
            }

            for (int i = 0; i < cnt; i++)
            {
                log.Debug("\nRec[" + (i + 1) + "]:" + cTxRecs[i]);
            }
        }

        [Test]
        public void TestReadLatestLoad()
        {
            log.Debug("Read Latest Loading Record...");
            APDUResponse response = this.icash2Player.ProcessSequence("ReadLatestLoad");
            log.Debug(response);
            //
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
            //
            CTxRec cTxRec = new CTxRec();
            cTxRec.TxRecHex = this.hexConverter.Bytes2Hex(response.Data);

            int p = 0;
            cTxRec.CardTxSn = BitConverter.ToUInt32
            (
                this.byteWorker.Reverse
                (
                    this.byteWorker.SubArray(response.Data, p, 4)
                ), 0
            );
            p += 4;
            cTxRec.TxDateTime = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, p, 7));
            p += 7;
            cTxRec.TId = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, p, 8));
            p += 8;
            cTxRec.RwId = Encoding.ASCII.GetString(this.byteWorker.SubArray(response.Data, p, 19));
            p += 19;
            cTxRec.TxType = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, p, 1));
            p += 1;
            cTxRec.CardPLSn = BitConverter.ToUInt32
            (
                this.byteWorker.Reverse
                (
                    this.byteWorker.SubArray(response.Data, p, 4)
                ), 0
            );
            p += 4;
            cTxRec.TxAmount = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, p, 4));
            p += 4;
            cTxRec.Balance = BitConverter.ToInt32
            (
                this.byteWorker.Reverse
                (
                    this.byteWorker.SubArray(response.Data, p, 4)
                ), 0
            );
            log.Debug("Last Load:" + cTxRec);
        }

        [Test]
        public void TestGetBalance()
        {
            log.Debug("Get balance...");
            APDUResponse response = this.icash2Player.ProcessSequence("GetValue");
            log.Debug(response);
            int balance = BitConverter.ToInt32(response.Data, 0);
            int balance1 = this.toInt32(response.Data);
            log.Debug("Balance:[" + balance1 + "]" );
            Assert.AreEqual(balance, balance1);
            //
            APDULog[] arrayLog = this.icash2Player.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        //[Test]
        public void ListTxRecords()
        {
            string txRecsHex =
                "00000039201304111501398604243F629F298053455430303130303030303030313130303231520000002C00000001000025AC0000003A20130411"
              + "1501398604243F629F298053455430303130303030303030313130303231520000002D00000001000025AD0000003B201304111501398604243F62"
              + "9F298053455430303130303030303030313130303231520000002E00000001000025AE0000003C201304111501398604243F629F29805345543030"
              + "3130303030303030313130303231540000000E00000001000025AD0000003D201304111806588604243F629F298053455430303130303030303030"
              + "313130303231530000002F00000001000025AE0000003E201304111806588604243F629F2980534554303031303030303030303131303032315300"
              + "00003000000001000025AF0000003F201304111806588604243F629F29805345543030313030303030303031313030323153000000310000000100"
              + "0025B000000040201304111806588604243F629F298053455430303130303030303030313130303231530000003200000001000025B10000004120"
              + "1304111806588604243F629F298053455430303130303030303030313130303231530000003300000001000025B200000042201304111806588604"
              + "243F629F298053455430303130303030303030313130303231530000003400000001000025B300000043201304111806588604243F629F29805345"
              + "5430303130303030303030313130303231530000003500000001000025B400000044201304111806588604243F629F298053455430303130303030"
              + "303030313130303231530000003600000001000025B5"
            ;
            byte[] txRecs = this.hexConverter.Hex2Bytes(txRecsHex);

            int recSize = 51;
            int cnt = txRecs.Length / recSize;
            CTxRec[] cTxRecs = new CTxRec[cnt];

            for (int i = 0; i < cnt; i++)
            {
                byte[] rec = this.byteWorker.SubArray(txRecs, i * recSize, recSize);
                CTxRec cTxRec = new CTxRec();
                cTxRec.TxRecHex = this.hexConverter.Bytes2Hex(rec);

                int p = 0;
                cTxRec.CardTxSn = BitConverter.ToUInt32
                (
                    this.byteWorker.Reverse
                    (
                        this.byteWorker.SubArray(rec, p, 4)
                    ), 0
                );
                p += 4;
                cTxRec.TxDateTime = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 7));
                p += 7;
                cTxRec.TId = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 8));
                p += 8;
                cTxRec.RwId = Encoding.ASCII.GetString(this.byteWorker.SubArray(rec, p, 19));
                p += 19;
                cTxRec.TxType = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 1));
                p += 1;
                cTxRec.CardPLSn = BitConverter.ToUInt32
                (
                    this.byteWorker.Reverse
                    (
                        this.byteWorker.SubArray(rec, p, 4)
                    ), 0
                );
                p += 4;
                cTxRec.TxAmount = this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(rec, p, 4));
                p += 4;
                cTxRec.Balance = BitConverter.ToInt32
                (
                    this.byteWorker.Reverse
                    (
                        this.byteWorker.SubArray(rec, p, 4)
                    ), 0
                );
                cTxRecs[i] = cTxRec;
            }

            for (int i = 0; i < cnt; i++)
            {
                log.Debug("\nRec[" + (i+1) + "]:" + cTxRecs[i] );
            }
        }


        [TearDown]
        public void TearDown()
        {
            this.icash2Player.CardNative.Disconnect(DISCONNECT.Reset);
        }

        public class CTxRec : Kms.Utility.AbstractDO
        {
            /// <summary>
            /// Tx Record Hex string: 51bytes -> 102Hex
            /// </summary>
            public string TxRecHex { get; set; }
            /// <summary>
            /// 卡片交易序號: 4bytes -> uint
            /// </summary>
            public UInt32 CardTxSn { get; set; }

            /// <summary>
            /// 交易時間: 7bytes BCD -> yyyyMMddHHmmss 
            /// </summary>
            public string TxDateTime { get; set; }

            /// <summary>
            /// Terminal ID: 8bytes -> Hex(16)
            /// </summary>
            public string TId { get; set; }

            /// <summary>
            /// RW ID: 19bytes(ASCII)
            /// </summary>
            public string RwId { get; set; }

            /// <summary>
            /// Transaction type: 1 byte -> Hex(2)
            /// </summary>
            public string TxType { get; set; }

            /// <summary>
            /// Card Payment or Loading Serial No: 4bytes -> uint, big endian
            /// </summary>
            public uint CardPLSn { get; set; }

            /// <summary>
            /// Transaction value: 4 bytes(BCD) -> 8 digits
            /// </summary>
            public string TxAmount { get; set; }

            /// <summary>
            /// Balance: 4 bytes -> uint, big endian
            /// </summary>
            public int Balance { get; set; }
        }

        private int toInt32(byte[] bytes)
        {
            int result = 0;
            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                result = ( result << 8 ) | bytes[i]; 
            }
            return result;
        }
    }
}
