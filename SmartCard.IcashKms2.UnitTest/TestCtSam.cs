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
    public class TestCtSam
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestCtSam));
        //
        IApplicationContext ctx;
        ICard cardNative = null;
        APDUPlayer icashPlayer = null;
        APDUPlayer tsamPlayer = null; 
        IHexConverter hexConverter = null;
        IByteWorker byteWorker = null;        

        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.cardNative = ctx["cardNative"] as ICard;
            this.icashPlayer = ctx[ "apduPlayer" ] as APDUPlayer;
            this.tsamPlayer = ctx["apduPlayer"] as APDUPlayer; 
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            //            
            this.icashPlayer.LoadCommandFile("CtIcashCmdList.xml");
            this.tsamPlayer.LoadCommandFile("CtSamCmdList.xml");
            //
            string[] readers = this.cardNative.ListReaders();
            if(readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            // find first icash card
            foreach(string reader in readers)
            {
                log.Debug("Connect: [" + reader + "]....");
                this.cardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                byte[] atrValue = this.cardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                this.cardNative.Disconnect(DISCONNECT.Unpower);
                string atrHex = this.hexConverter.Bytes2Hex(atrValue);
                //
                log.Debug("ATR:[" + atrHex + "]");
                // check if T/PL SAM
                if ("3BF71800008171FE42000063CA1102900089".Equals(atrHex))
                {
                    log.Debug("Got T/PL SAM in [" + reader + "]" );                    
                    this.tsamPlayer.CardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                }
                else if (atrHex.Substring(24, 4).Equals("950A")) //可能是門市卡,讀卡號檢核
                {
                    this.icashPlayer.CardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                    APDUResponse response = this.icashPlayer.ProcessSequence("GetCID");
                    string cid = Encoding.ASCII.GetString(this.byteWorker.SubArray(response.Data, 2, Math.Min(response.Data[1], response.Data.Length - 2)));
                    // if verify cid fail, disconnect...
                    log.Debug("Got icash cid:[" + cid + "]");
                }
                else
                {
                    log.Debug("reader:" + reader + " card unknow!");
                }
            }
        }

        [Test]
        public void TestSamVerifyPin()
        {
            log.Debug("sam Verify Pin...");
            APDUResponse response = this.tsamPlayer.ProcessCommand("ReadBinary");
            log.Debug(response);
            string pwd = this.hexConverter.Bytes2Hex( this.byteWorker.SubArray(response.Data, 4, 8) );
            SequenceParameter sp = new SequenceParameter();
            sp.Add( "PWD", pwd );
            response = this.tsamPlayer.ProcessSequence("VerifyPin", sp);
            log.Debug(response);
            APDULog[] arrayLog = this.tsamPlayer.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
                log.Debug(arrayLog[nI].ToString());
            log.Debug("sam SelectTsamObject....");
            response = this.tsamPlayer.ProcessCommand("SelectTsamObject");
            log.Debug(response);
            //
            log.Debug("icash ReadBinary...");
            response = this.icashPlayer.ProcessSequence("ReadBinary");
            string binaryHex = this.hexConverter.Bytes2Hex(response.Data);
            log.Debug(response);
            log.Debug("Rnd:[" + binaryHex + "]");

            log.Debug("icash Select_DF 7011...");
            sp = new SequenceParameter();
            sp.Add("DF", "7011");
            response = this.icashPlayer.ProcessSequence("Select_DF", sp);
            log.Debug(response);
            //
            log.Debug("icash Gen random...");
            response = this.icashPlayer.ProcessCommand("GenRandom");
            string rndHex = this.hexConverter.Bytes2Hex(response.Data);
            log.Debug(response);
            log.Debug("Rnd:[" + rndHex + "]" );
            //
            string kid = "7110000202".PadRight(16, 'F');
            log.Debug("[" + kid + "]");
            string data = kid + binaryHex + rndHex;
            log.Debug("size:" + data.Length + ":[" + data + "]" );
            sp = new SequenceParameter();
            sp.Add("MKN", "7");
            sp.Add("DATA", data);
            response = this.tsamPlayer.ProcessSequence("EncWithDK", sp);
            log.Debug(response);
            string encData = this.hexConverter.Bytes2Hex(response.Data);
            //
            log.Debug("icash TermAuth...");
            sp = new SequenceParameter();
            sp.Add("DATA", encData);
            response = this.icashPlayer.ProcessSequence("TermAuth", sp);
            log.Debug(response);


        }

        [TearDown]
        public void TearDown()
        {
            this.icashPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
            this.tsamPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
        }
    }
}
