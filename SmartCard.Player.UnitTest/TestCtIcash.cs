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
using SmartCard.ContactIcash;
using Kms2.Crypto.Common;

namespace SmartCard.Player.UnitTest
{
    [TestFixture]
    public class TestCtIcash
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestCtIcash));
        //
        IApplicationContext ctx;
        IDictionary<string, CardHandleDO> dicCardHandleDO = null;
        APDUPlayer apduPlayer = null; 
        IHexConverter hexConverter = null;
        IByteWorker byteWorker = null;        

        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.apduPlayer = ctx[ "apduPlayer" ] as APDUPlayer; 
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.dicCardHandleDO = new Dictionary<string, CardHandleDO>();
            //            
            //this.apduPlayer.LoadAPDUFile("CtIcashCmdList.xml");
            //this.apduPlayer.LoadSequenceFile("CtIcashCmdList.xml");
            this.apduPlayer.LoadCommandFile("CtIcashCmdList.xml");
            //
            string[] readers = this.apduPlayer.CardNative.ListReaders();
            if(readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            //else
            //{
            //    foreach( string reader in readers )
            //    {
            //        log.Debug( reader );
            //    }
            //}
            // find first icash card
            foreach( string reader in readers )
            {
                log.Debug( m => m( "Connect: [{0}]...", reader ) );
                this.apduPlayer.CardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                byte[] atrValue = this.apduPlayer.CardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);                
                log.Debug( m => m( "ATR:[{0}]", this.hexConverter.Bytes2Hex(atrValue) ) );
                //if ("3BF718000081" //718042000063950A019000B0"
                if( this.hexConverter.Bytes2Hex(atrValue).StartsWith("3BF7180000817") )
                {
                    log.Debug("Got it...");
                    break;
                }
                else
                {
                    this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
                }
            }
        }

        [Test]
        public void TestCardKinds()
        {
            this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);

            CardHandleDO chDo = new CardHandleDO()
            {
                CardName = "CT-TSAM"
               ,AtrHex = "3BF71800008171FE42000063CA1102900089"              
            };
            this.dicCardHandleDO[chDo.CardName] = chDo;
            //
            chDo = new CardHandleDO()
            {
                CardName = "CT-icash"
               ,AtrHex = "3BF718000081718042000063950A019000B0"              
            };
            this.dicCardHandleDO[chDo.CardName] = chDo;
            //            
            string[] readers = this.apduPlayer.CardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            //
            foreach (string reader in readers)
            {
                log.Debug( m => m( "Connect: [{0}]....", reader ) );
                try
                {
                    this.apduPlayer.CardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                    // Get Card Atr...
                    byte[] atrValue = this.apduPlayer.CardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    log.Debug( m => m( "ATR:[{0}]", this.hexConverter.Bytes2Hex(atrValue) ) );
                    // disconnect...
                    this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
                    foreach( string cardName in dicCardHandleDO.Keys )
                    {
                        CardHandleDO ch = dicCardHandleDO[cardName];
                        if (ch.AtrHex.Equals(atrValue))
                        {
                            ch.ReaderName = reader;
                            ch.ApduPlayer = apduPlayer;
                        }
                    }
                }
                catch (Exception)
                {
                    log.Debug("Cannot get ATR!");
                }
            }
           
        }

        [Test]
        public void TestProcessCommand()
        {
            log.Debug("SelectMDF...");
            APDUResponse response = this.apduPlayer.ProcessCommand
            (
                "SelectMDF"
            );
            log.Debug(response);

            log.Debug("SelectDF 7110...");
            APDUParam param = new APDUParam();
            param.Data = new byte[] { 0x71, 0x10 };
            response = this.apduPlayer.ProcessCommand
            (
                "SelectDF", param
            );
            log.Debug(response);

            log.Debug("SelectEF 7101...");
            param.Data = new byte[] { 0x71, 0x01 };
            response = this.apduPlayer.ProcessCommand
            (
                "SelectEF", param
            );
            log.Debug(response);

            log.Debug("ReadRecord size of CID...");
            //
            param.Reset();
            //param.Data = null;
            param.P1 = 2;
            param.Le = new byte[] { 0x00 };
            response = this.apduPlayer.ProcessCommand
            (
                "ReadRecord", param
            );
            log.Debug(response);
            log.Debug("RECORD SIZE IS: " + response.Data[1]);
            //
            log.Debug("Get CID...");
            param.Reset();
            param.P1 = 2;
            param.Le = new byte[] { (byte)( 2  + response.Data[1]) };
            response = this.apduPlayer.ProcessCommand
            (
                "ReadRecord", param
            );
            log.Debug(response);
            log.Debug("CID IS: " + Encoding.ASCII.GetString( this.byteWorker.SubArray( response.Data,2, response.Data[1] )) );
            //
            //
            log.Debug("Read Binary...");
            response = this.apduPlayer.ProcessSequence
            (
                "ReadBinary"
            );
            log.Debug(response);
            log.Debug("ChipID:[" + this.hexConverter.Bytes2Hex( response.Data ) + "]" );
            //
            log.Debug("Generate Random...");
            param.Reset();
            response = this.apduPlayer.ProcessCommand
            (
                "GenRandom", param
            );
            log.Debug(response);
            log.Debug("Random:[" + this.hexConverter.Bytes2Hex(response.Data) + "]");
        }

        [Test]
        public void TestGetCID()
        {
            //SequenceParameter sp = new SequenceParameter();
            //sp.Add("Record", "2");
            //sp.Add("Le", "18");
            //APDUResponse response = this.apduPlayer.ProcessSequence("GetCID", sp );
            APDUResponse response = this.apduPlayer.ProcessSequence("GetCID");
            log.Debug(response);
            string cid = Encoding.ASCII.GetString( this.byteWorker.SubArray(response.Data, 2, Math.Min( response.Data[1], response.Data.Length - 2) ));
            log.Debug( "cid:[" + cid + "]" );
            log.Debug("Log List...");
            APDULog[] arrayLog = this.apduPlayer.Log.ToArray();
            for (int nI = 0; nI < this.apduPlayer.Log.Count; nI++)
                log.Debug(arrayLog[nI].ToString());
            
        }

        [Test]
        public void TestGetIDollar()
        {
            APDUResponse response = this.apduPlayer.ProcessSequence("GetIDollar");
            log.Debug(response);
            byte[] idollarRec = this.byteWorker.SubArray(response.Data, 2, Math.Min(response.Data[1], response.Data.Length - 2));
            //log.Debug(idollarRec.Length);
            byte[] idollarBytes = this.byteWorker.SubArray(idollarRec, 16, 4);
            uint idollar = Convert.ToUInt32( this.hexConverter.Bytes2Hex(idollarBytes), 10 );
            log.Debug("idollar:[" + idollar + "]");
            log.Debug("Log List...");
            APDULog[] arrayLog = this.apduPlayer.Log.ToArray();
            for (int nI = 0; nI < this.apduPlayer.Log.Count; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestGetHistory()
        {
            for (int i = 1; i <= 5; i++)
            {
                SequenceParameter sp = new SequenceParameter();
                sp.Add( "Record", Convert.ToString(i) );
                             
                APDUResponse response = this.apduPlayer.ProcessSequence("GetHistory", sp);                
                log.Debug(response);
                if (response.Data != null)
                {
                    byte[] hist = this.byteWorker.SubArray(response.Data, 2, response.Data.Length - 2);
                    log.Debug("history(" + i + "):[" + this.hexConverter.Bytes2Hex(hist) + "]");
                }
                log.Debug("Log List...");
                APDULog[] arrayLog = this.apduPlayer.Log.ToArray();
                for (int nI = 0; nI < this.apduPlayer.Log.Count; nI++)
                    log.Debug(arrayLog[nI].ToString());
            }
        }

        [Test]
        public void TestReadBalance()
        {
            APDUResponse response = this.apduPlayer.ProcessSequence("ReadBalance");
            log.Debug(response);
            string balance = Encoding.ASCII.GetString( response.Data );
            log.Debug("balance:[" + balance + "]");
            log.Debug("Log List...");
            APDULog[] arrayLog = this.apduPlayer.Log.ToArray();
            for (int nI = 0; nI < this.apduPlayer.Log.Count; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestReadBinary()
        {
            APDUResponse response = this.apduPlayer.ProcessSequence("ReadBinary");
            log.Debug(response);
            string chipId = this.hexConverter.Bytes2Hex(response.Data);
            log.Debug("ChipId:[" + chipId + "]");
            log.Debug("Log List...");
            APDULog[] arrayLog = this.apduPlayer.Log.ToArray();
            for (int nI = 0; nI < this.apduPlayer.Log.Count; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [Test]
        public void TestSelectDF()
        {
            log.Debug("SelectDF, default 7011...");
            APDUResponse response = this.apduPlayer.ProcessSequence("Select_DF");
            log.Debug(response);           
            APDULog[] arrayLog = this.apduPlayer.Log.ToArray();
            for (int nI = 0; nI < this.apduPlayer.Log.Count; nI++)
                log.Debug(arrayLog[nI].ToString());

            log.Debug("SelectDF 7110...");
            SequenceParameter sp = new SequenceParameter();
            sp.Add( "DF", "7110" );
            response = this.apduPlayer.ProcessSequence("Select_DF", sp );
            log.Debug(response);
            arrayLog = this.apduPlayer.Log.ToArray();
            for (int nI = 0; nI < this.apduPlayer.Log.Count; nI++)
                log.Debug(arrayLog[nI].ToString());
        }

        [TearDown]
        public void TearDown()
        {
            this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
        }
    }
}
