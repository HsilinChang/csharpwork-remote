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
using Kms.Crypto;

namespace SmartCard.Player.UnitTest
{
    [TestFixture]
    public class TestSamAv2
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestSamAv2));
        //
        private IApplicationContext ctx;
        private ICard cardNative;
        private APDUPlayer apduPlayer = null;
        private IHexConverter hexConverter = null;
        private IByteWorker byteWorker = null;
        private IKeyDeriver keyDeriver;
        private IRandWorker randWorker;
        private ISymCryptor symCryptor = null;
        private ICMacWorker cMacWorker = null;
        private ICrcWorker<uint> nxpCrc32Worker = null;
        private Iso14443ACrcWorker nxpCrc16Worker = null;
        private bool chkOK = false;

        private IDictionary<string, string> dicKey = new Dictionary<string, string>()
		{
            { "seed00CMKHex",       "4631317770440EDA46E875C974ADE505" }
           ,{ "seed30KeyMasterHex", "98AE6B9684B4700E3042AF03E00ADB56" }
           ,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }
           ,{ "seed35TxLogMacHex",  "A672F20A9062B8FD00D0A592846E881C" }
		}
        ;

        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.apduPlayer = ctx["apduPlayer"] as APDUPlayer;
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.keyDeriver = ctx["aes128KeyDeriver"] as IKeyDeriver;
            this.randWorker = ctx["randWorker"] as IRandWorker;
            //
            this.cMacWorker = ctx["aes128CMacWorker"] as ICMacWorker;
            this.nxpCrc16Worker = ctx["nxpCrc16Worker"] as Iso14443ACrcWorker;
            this.nxpCrc32Worker = ctx["nxpCrc32Worker"] as ICrcWorker<uint>;
            //
            this.symCryptor = ctx["symCryptor"] as SymCryptor;
            //
            this.cardNative = this.apduPlayer.CardNative;
            this.apduPlayer.LoadCommandFile("SamAv2CmdList.xml");
            //
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            // find first SAM AV2 card
            foreach (string reader in readers)
            {
                try
                {
                    log.Debug("Connect: [" + reader + "]....");
                    this.apduPlayer.CardNative.Connect(reader, SHARE.Exclusive, PROTOCOL.T0orT1);
                    byte[] atrValue = this.apduPlayer.CardNative.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    log.Debug("ATR:[" + this.hexConverter.Bytes2Hex(atrValue) + "]");
                    if
                    (
                        this.hexConverter.Bytes2Hex(atrValue).StartsWith("3BDF18FF81F1FE43003F03834D494641524520506C75732053414D3B")
                    )
                    {
                        log.Debug("Got it...");
                        chkOK = true;
                        break;
                    }
                    else
                    {
                        this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
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
        public void TestGetMasterKey()
        {
            byte[] divKey = this.getDivKey("seed00CMKHex");
            SequenceParameter sp = new SequenceParameter();
            //
            log.Debug("SAM_Unlock_1...");
            sp.Add("KNR_KVER", "0000");                
            APDUResponse response = this.apduPlayer.ProcessSequence("SAM_Unlock_1", sp);
            log.Debug(response);
            //
            Assert.AreEqual(0x90, response.SW1);
            Assert.AreEqual(0xAF, response.SW2);
            //
            byte[] rnd2 = response.Data;   
            byte[] rnd1 = this.randWorker.GetBytes(12);
            //
            log.Debug( "Rnd2:[" + this.hexConverter.Bytes2Hex(rnd2) + "]" );
            log.Debug( "Rnd1:[" + this.hexConverter.Bytes2Hex(rnd1) + "]" );
            //
            byte[] iv = this.byteWorker.Fill( 16, 0x00 );
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.SetMacKey(divKey);
            byte[] macData = this.byteWorker.Combine(
                    rnd2
                  , new byte[] { 0x00 }
                  , new byte[] { 0x00, 0x00, 0x00 } 
            );
            this.cMacWorker.DataInput( macData );
            byte[] mact = this.cMacWorker.GetOdd();
            byte[] msg = this.byteWorker.Combine(
                mact, rnd1
            );
            
            log.Debug("SAM_Unlock_2...");
            sp.Clear();            
            sp.Add("MSG", this.hexConverter.Bytes2Hex( msg ) );
            response = this.apduPlayer.ProcessSequence("SAM_Unlock_2", sp);
            log.Debug(response);
            //
            Assert.AreEqual(0x90, response.SW1);
            Assert.AreEqual(0xAF, response.SW2);
            //
            byte[] macSam1 = this.byteWorker.SubArray(response.Data, 0, 8);
            log.Debug("MacSam1:[" + this.hexConverter.Bytes2Hex( macSam1 ) + "]" );
            byte[] encSam1 = this.byteWorker.SubArray(response.Data, 8, 16);
            log.Debug("EncSam1:[" + this.hexConverter.Bytes2Hex( encSam1 ) + "]");
            //
            // verify macSam1
            macData = this.byteWorker.Combine(
                rnd1
              , new byte[] { 0x00 }
              , new byte[] { 0x00, 0x00, 0x00 } 
            );
            this.cMacWorker.DataInput(macData);
            mact = this.cMacWorker.GetOdd();
            Assert.AreEqual(mact, macSam1);
            //
            // decrypt encSam1 with kxe -> rndB, D(kxe,encSam1)
            //    get sv1,Rndl[7..11] || Rnd2[7..11] || ( Rndl[0..4] XOR Rnd2[0..4] ) || 0x91
            // get kxe
            byte[] sv1 = this.byteWorker.Combine
            (
                this.byteWorker.SubArray(rnd1, 7, 5)
              , this.byteWorker.SubArray(rnd2, 7, 5)
              , this.byteWorker.ExclusiveOr
                (
                    this.byteWorker.SubArray(rnd1, 0, 5)
                  , this.byteWorker.SubArray(rnd2, 0, 5)
                )
              , new byte[] { 0x91 }
             );
            this.symCryptor.SetIv(SymCryptor.ConstZero);
            this.symCryptor.SetKey(divKey);
            byte[] kxe = this.symCryptor.Encrypt(sv1);
            // decrypt encSam1 with kxe to get rndB
            this.symCryptor.SetIv( iv );
            this.symCryptor.SetKey(kxe);
            byte[] rndB = this.symCryptor.Decrypt(encSam1);
            log.Debug("RndB:[" + this.hexConverter.Bytes2Hex(rndB) + "]");
            //
            byte[] rndA = this.randWorker.GetBytes(16);
            // get encHost E(kxe, rndA||rndBROL2)
            byte[] encHost = this.symCryptor.Encrypt( 
                this.byteWorker.Combine
                (
                    rndA, this.byteWorker.RotateLeft(rndB, 2)
                )
            );
            //
            log.Debug("SAM_Unlock_3...");
            sp.Clear();
            sp.Add("MSG", this.hexConverter.Bytes2Hex(encHost));
            response = this.apduPlayer.ProcessSequence("SAM_Unlock_3", sp);
            log.Debug(response);
            //
            Assert.AreEqual(0x90, response.SW1);
            Assert.AreEqual(0x00, response.SW2);
            // verify RndA from encSam2
            byte[] encSam2 = response.Data;
            byte[] encRndAROL2 = this.symCryptor.Encrypt(this.byteWorker.RotateLeft(rndA, 2));
            Assert.AreEqual(encRndAROL2, encSam2);
            //
            //// svKe: RndA[11..15] || RndB[11..15] || ( RndA[4..8] XOR RndB[4..8] ) || 0x81
            //byte[] svKe = this.byteWorker.Combine
            //(
            //    this.byteWorker.SubArray( rndA, 11, 5 )
            //   ,this.byteWorker.SubArray( rndB, 11, 5 )
            //   ,this.byteWorker.ExclusiveOr
            //    ( 
            //        this.byteWorker.SubArray( rndA, 4, 5 )
            //      , this.byteWorker.SubArray( rndB, 4, 5 ) 
            //    )
            //   ,new byte[] { 0x81 }
            //);
            //// svKm: RndA[7..11] || RndB[7..11] ] || ( RndA[0..4] XOR RndB[0..4] ) || 0x82
            //byte[] svKm = this.byteWorker.Combine
            //(
            //     this.byteWorker.SubArray(rndA, 7, 5)
            //   , this.byteWorker.SubArray(rndB, 7, 5)
            //   , this.byteWorker.ExclusiveOr
            //    (
            //        this.byteWorker.SubArray(rndA, 0, 5)
            //      , this.byteWorker.SubArray(rndB, 0, 5)
            //    )
            //   , new byte[] { 0x82 }
            //);
            //this.symCryptor.SetIv(iv);
            //this.symCryptor.SetKey(divKey);
            //byte[] ke = this.symCryptor.Encrypt(svKe);
            //byte[] km = this.symCryptor.Encrypt(svKm);
        }

        //[Test]
        public void TestCMAC()
        {
            byte[] divKey = this.hexConverter.Hex2Bytes("163C1DFF81597E554578326BC4240500");
            byte[] iv = this.byteWorker.Fill(16, 0x00);
            this.cMacWorker.SetIv(iv);
            this.cMacWorker.SetMacKey(divKey);
            this.cMacWorker.DataInput(this.hexConverter.Hex2Bytes("7aaef0321ec2c8707577dabe00000000"));
            byte[] cmac = this.cMacWorker.GetOdd();
            log.Debug("MacT:[" + this.hexConverter.Bytes2Hex(cmac) + "]");

        }

        [Test]
        public void TestGetVersion()
        {
            log.Debug("Get Version...");
            APDUResponse response = this.apduPlayer.ProcessSequence("SAM_GetVersion");
            log.Debug(response);
            //
            Assert.AreEqual(0x90, response.SW1);
            Assert.AreEqual(0x00, response.SW2);

            byte[] resBytes = response.Data;
            //string expected = "0401010302280104010103022801042C2E0AAB36809710250000140B0D00A2";
            byte[] uid = this.byteWorker.SubArray(resBytes, 14, 7);
            log.Debug(this.hexConverter.Bytes2Hex(uid));
        }

        private byte[] getUid()
        {
            log.Debug("Get Version...");
            APDUResponse response = this.apduPlayer.ProcessSequence("SAM_GetVersion");
            if (!(response.SW1 == 0x90 && response.SW2 == 0x00))
            {
                return null;
            }
            byte[] resBytes = response.Data;
            return this.byteWorker.SubArray(response.Data, 14, 7);
        }

        [TearDown]
        public void TearDown()
        {
            this.apduPlayer.CardNative.Disconnect(DISCONNECT.Unpower);
        }
        //
        private byte[] getDivInputIcash(byte[] uid)
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

        private byte[] getDivInputTid(byte[] uid)
        {
            return this.byteWorker.Combine
            (
                  new byte[] { 0x86 }, uid
                , Encoding.ASCII.GetBytes("SEVEN")
                , new byte[] { 0x86 }, uid
                , Encoding.ASCII.GetBytes("11")
                , new byte[] { 0x86 }, uid
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
            byte[] uid = this.getUid();
            byte[] divKey = null;
            if (
                 "seed00CMKHex".Equals(seedKeyId)
            )
            {
                this.keyDeriver.SetSeedKey(seedKey);
                this.keyDeriver.DiverseInput(this.getDivInputIcash(uid));
                divKey = this.keyDeriver.GetDerivedKey();
                log.Debug("DiverseKey:[" + this.hexConverter.Bytes2Hex(divKey) + "]");
            }
            return divKey;
        }
    }
}
