using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using System.Security.Cryptography;
//
using Spring.Context;
using Spring.Context.Support;
using Common.Logging;
//
using NUnit.Framework;
//
using SmartCard.Pcsc;
using SmartCard.Player;
using SmartCard.SamAV2;
using Kms2.Crypto.Common;
using Kms2.Crypto.Utility;

namespace SmartCard.SamAV2.UnitTest
{
    [TestFixture]
    public class TestSamAv2
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestSamAv2));
        //
        private IApplicationContext ctx;
        private SamAV2Manager samAV2Manager = null;
        private IHexConverter hexConverter = null;
        private IByteWorker byteWorker = null;
        private IKeyDeriver keyDeriver;
        private byte[] uid = null;
        private ISymCryptor aesCryptor = null;
        //
        private IDictionary<string, KeyEntryDO> dicKeyEntry = null;
        private IDictionary<string, KeyInfo> dicKeyInfo = null;
        //        0002	SAM New Card Master Key	
        //        01	4631317770440EDA46E875C974ADE505	6370EDC17D695BD4
        //        02	75738D8D534FB7EB719DFB749E750428	B6A8B28E76B812EB
        //        03	CDD222333ED33527BA289AC6841B210C	43144709EAA85E22
        //        0030	Key management(Owner)	
        //        01	98AE6B9684B4700E3042AF03E00ADB56	BBD472290AA16F3A
        //        02	9C4354F7A862E106F7D483F0731C1A9A	F00E93C01B49D5C8
        //        03	CBFA9A3669E3FDAD195D07233928BABA	314EF62B19BA93EE
        //        0031	Authenticate with server	
        //        01	5C9A1031BE73561663B393DBFEFDEE5A	B69C5E5DE784304B
        //        02	6A7C6F50382896440FA76BC1CEF9CFA9	E81949418F90645D
        //        03	4AEC089318FDD31D821407158FF13ECB	7EA4439211833F3F
        //        0032	Card access-Get Info.(0xA)	
        //        01	FDA01F10E42489733FE1EE514AC55E92	90DF1362C2FB2E46
        //        02	09DCB16DFBC5D96FCD6BD5E65C337911	E50DE19CBE2FB0E5
        //        03	BB24FAB73F9E7BD84951D5754CA36537	CC7F8E7B8EEDECB9
        //        0033	Card access-Payment(0xB)	
        //        01	EEEA4C617D2880C83BC2358AF645EBDC	FE6D7F606BE91ABE
        //        02	9CA1E59063F81D161CAD461F1F437194	59259BDDB23C2643
        //        03	7DDE9B3744BD2D5D3B530216FC9014CC	4C6E052BDF464428
        //        0034	Card access-Charge(0xC)	
        //        01	082CBB7C855C366CCFBF4A07444BA989	17521869272383DF
        //        02	55AF06294D9543153B2B5DA825C6AA01	82F0E7FF80F60C9C
        //        03	45E1F8444B1344EBAB4273B76780365E	811A683FAB2B62CF
        //        0035	TxLog signature TSAM	
        //        01	A672F20A9062B8FD00D0A592846E881C	32BCF0C30340F78F
        //        02	AAD18B1CB1F4CA5CACFF5B4D027DD487	78FD1CB43CDAE1D8
        //        03	E6179307E1386459EBD1E5789C29C4A1	A9D31704246DA508
        //private IDictionary<string, string> dicKey = new Dictionary<string, string>()
        //{
        //   { "seed00CMKHex",       "4631317770440EDA46E875C974ADE505" }
        //   // { "seed00CMKHex",       "75738D8D534FB7EB719DFB749E750428" }
        //   // { "seed00CMKHex",       "CDD222333ED33527BA289AC6841B210C" }
        //   ,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }
        //    //,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }
        //    //,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }

        //   //,{ "seed30KeyMasterHex", "98AE6B9684B4700E3042AF03E00ADB56" }
        //   //,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }
        //   //,{ "seed35TxLogMacHex",  "A672F20A9062B8FD00D0A592846E881C" }
        //}
        //;
        
        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.keyDeriver = ctx["aes128KeyDeriver"] as IKeyDeriver;
            this.aesCryptor = ctx["aesCryptor"] as ISymCryptor;
            //
            if (null == this.dicKeyEntry)
            {
                this.dicKeyEntry = new Dictionary<string, KeyEntryDO>();
                // add seedMasterKey, with AES128
                KeyEntryDO keyEntry = new KeyEntryDO
                {
                    KeyName = "seedMasterKey",
                    KeyNo = 0x00,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0xFF,
                    SET = new byte[] { 0x20, 0x04 },
                    ExtSet = 0x00,
                    KeyA = this.hexConverter.Hex2Bytes("4631317770440EDA46E875C974ADE505"),
                    KeyB = this.hexConverter.Hex2Bytes("75738D8D534FB7EB719DFB749E750428"),
                    KeyC = this.hexConverter.Hex2Bytes("CDD222333ED33527BA289AC6841B210C"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                // set default keyEntry 
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedWriteKey",
                    KeyNo = 0x30,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0xFF, 
                    SET = new byte[] { 0x20, 0x01 },
                    ExtSet = 0x00,
                    KeyA = this.hexConverter.Hex2Bytes("98AE6B9684B4700E3042AF03E00ADB56"),
                    KeyB = this.hexConverter.Hex2Bytes("9C4354F7A862E106F7D483F0731C1A9A"),
                    KeyC = this.hexConverter.Hex2Bytes("CBFA9A3669E3FDAD195D07233928BABA"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedServAuthKey",
                    KeyNo = 0x31,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = new byte[] { 0x20, 0x00 },
                    ExtSet = 0x04,
                    KeyA = this.hexConverter.Hex2Bytes("5C9A1031BE73561663B393DBFEFDEE5A"),
                    KeyB = this.hexConverter.Hex2Bytes("6A7C6F50382896440FA76BC1CEF9CFA9"),
                    KeyC = this.hexConverter.Hex2Bytes("4AEC089318FDD31D821407158FF13ECB"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "icashKeyTemp",
                    KeyNo = 0x30,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0xFF,
                    SET = new byte[] { 0x00, 0x00 },
                    ExtSet = 0x00,
                    KeyA = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyB = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyC = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "defaultKey",
                    KeyNo = 0x00,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x00,
                    CEK_VER = 0x00,
                    KUC = 0xFF,
                    SET = new byte[] { 0x20, 0x00 },
                    ExtSet = 0x00,
                    KeyA = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyB = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    KeyC = this.hexConverter.Hex2Bytes("00000000000000000000000000000000"),
                    VerA = 0x00,
                    VerB = 0x00,
                    VerC = 0x00,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedInfoKey",
                    KeyNo = 0x32,
                    DF_AID = new byte[] { 0x11, 0x87, 0x16 },
                    DF_KEY_NO = 0x0A,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET =  //new byte[] { 0x25, 0xF8 }, 
                           new byte[] { 0x24, 0x00 },
                    ExtSet = 0x11,
                    KeyA = this.hexConverter.Hex2Bytes("FDA01F10E42489733FE1EE514AC55E92"),
                    KeyB = this.hexConverter.Hex2Bytes("09DCB16DFBC5D96FCD6BD5E65C337911"),
                    KeyC = this.hexConverter.Hex2Bytes("BB24FAB73F9E7BD84951D5754CA36537"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedPaymentKey",
                    KeyNo = 0x33,
                    DF_AID = new byte[] { 0x11, 0x87, 0x16 },
                    DF_KEY_NO = 0x0B,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET =
                        //new byte[] { 0x25, 0xF8 }, 
                        new byte[] { 0x24, 0x00 },
                    ExtSet = 0x11,
                    KeyA = this.hexConverter.Hex2Bytes("EEEA4C617D2880C83BC2358AF645EBDC"),
                    KeyB = this.hexConverter.Hex2Bytes("9CA1E59063F81D161CAD461F1F437194"),
                    KeyC = this.hexConverter.Hex2Bytes("7DDE9B3744BD2D5D3B530216FC9014CC"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedChargeKey",
                    KeyNo = 0x34,
                    DF_AID = new byte[] { 0x11, 0x87, 0x16 },
                    DF_KEY_NO = 0x0C,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET =
                        //new byte[] { 0x25, 0xF8 }, 
                        new byte[] { 0x24, 0x00 },
                    ExtSet = 0x11,
                    KeyA = this.hexConverter.Hex2Bytes("082CBB7C855C366CCFBF4A07444BA989"),
                    KeyB = this.hexConverter.Hex2Bytes("55AF06294D9543153B2B5DA825C6AA01"),
                    KeyC = this.hexConverter.Hex2Bytes("45E1F8444B1344EBAB4273B76780365E"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                //
                keyEntry = new KeyEntryDO
                {
                    KeyName = "seedMacKey",
                    KeyNo = 0x35,
                    DF_AID = new byte[] { 0x00, 0x00, 0x00 },
                    DF_KEY_NO = 0x00,
                    CEK_NO = 0x30,
                    CEK_VER = 0x00,
                    KUC = 0x01,
                    SET = new byte[] { 0x20, 0x00 },
                    ExtSet = 0x04,
                    KeyA = this.hexConverter.Hex2Bytes("A672F20A9062B8FD00D0A592846E881C"),
                    KeyB = this.hexConverter.Hex2Bytes("AAD18B1CB1F4CA5CACFF5B4D027DD487"),
                    KeyC = this.hexConverter.Hex2Bytes("E6179307E1386459EBD1E5789C29C4A1"),
                    VerA = 0x00,
                    VerB = 0x01,
                    VerC = 0x02,
                    SamMode = "AV2"
                };
                dicKeyEntry.Add(keyEntry.KeyName, keyEntry);
                
            }

            if (null == this.dicKeyInfo)
            {
                this.dicKeyInfo = new Dictionary<string, KeyInfo>();
                // set keyInfo
                KeyInfo keyInfo = new KeyInfo
                {
                    KeyName = "usageKeyDefault",
                    KeyNo = 0x00,
                    KeyVer = 0x00,
                    KeyData = this.hexConverter.Hex2Bytes("00000000000000000000000000000000")
                };
                this.dicKeyInfo.Add(keyInfo.KeyName, keyInfo);            
            }
            //
            this.samAV2Manager = ctx["samAV2Manager"] as SamAV2Manager;
            // set APDU commands 
            if( this.samAV2Manager.Connect() )
            {
                this.uid = this.samAV2Manager.GetUid();
                log.Debug(m => m("uid: {0}", this.hexConverter.Bytes2Hex(this.uid))); 
            }
        }

        [Test]
        public void Test01GetUid()
        {
            byte[] uid = this.samAV2Manager.GetUid();
            log.Debug(m => m("uid:[{0}]", this.hexConverter.Bytes2Hex(uid) ) );
            Assert.NotNull(uid);
        }

        [Test]
        public void Test02AuthHostDefault()
        {
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            Assert.True(this.samAV2Manager.AuthenticateHostDefault(authHostDO));
            log.Debug(authHostDO);
        }

        [Test]
        public void Test03ChangeDefaultMaster2Aes()
        {
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            Assert.True(this.samAV2Manager.AuthenticateHostDefault(authHostDO));
            log.Debug(authHostDO);
            //
            KeyEntryDO seedMaster = this.dicKeyEntry["seedMasterKey"];
            KeyEntryDO divMaster = new KeyEntryDO
            {
                KeyName = "divMasterKey",
                KeyNo = seedMaster.KeyNo,
                DF_AID = seedMaster.DF_AID,
                DF_KEY_NO = seedMaster.DF_KEY_NO,
                CEK_NO = seedMaster.CEK_NO,
                CEK_VER = seedMaster.CEK_VER,
                KUC = seedMaster.KUC,
                SET = seedMaster.SET,
                KeyA = this.getDivKeyIcash("seedMasterKey", "A" ),
                KeyB = this.getDivKeyIcash("seedMasterKey", "B" ),
                KeyC = this.getDivKeyIcash("seedMasterKey", "C"),
                VerA = seedMaster.VerA,
                VerB = seedMaster.VerB,
                VerC = seedMaster.VerC,
                SamMode = seedMaster.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divMaster));
            Assert.True(this.samAV2Manager.ChangeKeyEntry(divMaster, authHostDO));
        }

        [Test]
        public void Test04AuthMasterAes()
        {           
            // unlock sam
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            byte keyVer = 0x02; // C 
            byte[] keyData = this.getDivKeyIcash( "seedMasterKey", keyVer );
            Assert.True( this.samAV2Manager.AuthenticateHostAES( keyData, 0x00, keyVer, 0x00, authHostDO));
            log.Debug(authHostDO);
        }


        [Test]
        public void Test04Rest2Default()
        {
            this.samAV2Manager.DisConnect();
            TrtSamAV1Manager samAV1Manager = ctx["trtSamAV1Manager"] as TrtSamAV1Manager;
            if (samAV1Manager.Connect())
            {
                this.uid = samAV1Manager.GetUid();
                log.Debug(m => m("uid: {0}", this.hexConverter.Bytes2Hex(this.uid)));
            }
            // unlock sam
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            byte keyVer = 0x00; // A
            byte[] keyData = this.getDivKeyIcash( "seedMasterKey", keyVer );
                //this.byteWorker.Fill(16, 0x00);
            Assert.True(samAV1Manager.AuthenticateHostAES( keyData, 0x00, keyVer, 0x00, authHostDO ));
            log.Debug(authHostDO);
            // change write key 0x30
            //Assert.True(samAV1Manager.AuthenticateHost(keyData, 0x30, keyVer, 0x00, authHostDO));
            KeyEntryDO seedWrite = this.dicKeyEntry["seedWriteKey"];
            KeyEntryDO divWrite = new KeyEntryDO
            {
                KeyName = "divWriteKey",
                KeyNo = seedWrite.KeyNo,
                DF_AID = seedWrite.DF_AID,
                DF_KEY_NO = seedWrite.DF_KEY_NO,
                CEK_NO = seedWrite.CEK_NO,
                CEK_VER = seedWrite.CEK_VER,
                KUC = seedWrite.KUC,
                SET = seedWrite.SET,
                KeyA = this.getDivKey711("seedWriteKey", "A"),
                KeyB = this.getDivKey711("seedWriteKey", "B"),
                KeyC = this.getDivKey711("seedWriteKey", "C"),
                VerA = seedWrite.VerA,
                VerB = seedWrite.VerB,
                VerC = seedWrite.VerC,
                ExtSet = seedWrite.ExtSet,
                SamMode = seedWrite.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divWrite));
            Assert.True(samAV1Manager.ChangeKeyEntryAES(divWrite, authHostDO));
            // authenticate 0x30
            byte keyNo = 0x30;
            keyVer = 0x00;
            keyData = this.getDivKey711("seedWriteKey", "A");
            Assert.True(samAV1Manager.AuthenticateHostAES(keyData, keyNo, keyVer, 0x00, authHostDO));
            log.Debug(authHostDO);
            KeyEntryDO defaultMaster = this.dicKeyEntry["icashKeyTemp"];
            defaultMaster.KeyNo = 0x00;
            defaultMaster.CEK_NO = 0x00;
            Assert.True(samAV1Manager.ChangeKeyEntryAES(defaultMaster, authHostDO));
            defaultMaster.KeyNo = 0x30;
            Assert.True(samAV1Manager.ChangeKeyEntryAES(defaultMaster, authHostDO));
            samAV1Manager.DisConnect();
            this.samAV2Manager.Connect();
        }

        [Test]
        public void Test05Switch2AV2Mode()
        {
            byte keyVer = 0x01;     // key B        
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            byte[] keyData = this.getDivKeyIcash( "seedMasterKey", keyVer );
            // swith to av2
            Assert.True( this.samAV2Manager.Switch2AV2Mode( keyData, keyVer, authHostDO ) );
        }

        [Test]
        public void Test06UnlockSam()
        {
            byte[] divKey = this.getDivKeyIcash( "seedMasterKey", "B" );
            Assert.True( this.samAV2Manager.Unlock( divKey, 0x00, 0x01, 0x00));
        }

        [Test]
        public void Test08AuthenticateHostWriteKey()
        {
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            byte keyVer = 0x00;
            byte[] divKey = this.getDivKeyIcash("seedMasterKey", keyVer );
               // this.byteWorker.Fill(16, 0x00);
            Assert.True(this.samAV2Manager.AuthenticateHost(divKey, 0x00, keyVer, 0x00, authHostDO));
            //Assert.True(this.samAV2Manager.Unlock(divKey, 0x00, keyVer, 0x00));
            // auth 0x30
            divKey = this.getDivKey711("seedWriteKey", keyVer);            
            Assert.True( this.samAV2Manager.AuthenticateHost(divKey, 0x30, keyVer, 0x00, authHostDO ));
            log.Debug(m => m("{0}", authHostDO));
        }

        [Test]
        public void Test98ResetWriteKey()
        {
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            byte keyVer = 0x00;
            byte[] divKey = this.getDivKeyIcash("seedMasterKey", keyVer);
            Assert.True(this.samAV2Manager.AuthenticateHost(divKey, 0x00, keyVer, 0x00, authHostDO));
            //Assert.True(this.samAV2Manager.Unlock(divKey, 0x00, keyVer, 0x00));           

            //auth 0x30
            divKey = this.getDivKey711("seedWriteKey", keyVer);
            Assert.True(this.samAV2Manager.AuthenticateHost(divKey, 0x30, keyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));

            // change server authentication key 0x31
            KeyEntryDO defaultKey = this.dicKeyEntry["defaultKey"];
            defaultKey.KeyNo = 0x31;
            log.Debug(m => m("Change keyentry: {0}", defaultKey));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(defaultKey, authHostDO));
            // change icash2 info key
            defaultKey.KeyNo = 0x32;
            log.Debug(m => m("Change keyentry: {0}", defaultKey));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(defaultKey, authHostDO));
            // change payment key
            defaultKey.KeyNo = 0x33;
            log.Debug(m => m("Change keyentry: {0}", defaultKey));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(defaultKey, authHostDO));
            // change charge key
            defaultKey.KeyNo = 0x34;
            log.Debug(m => m("Change keyentry: {0}", defaultKey));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(defaultKey, authHostDO));
            // change txlog sign key
            defaultKey.KeyNo = 0x35;
            log.Debug(m => m("Change keyentry: {0}", defaultKey));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(defaultKey, authHostDO));
            //
            // change writekey
            defaultKey.KeyNo = 0x30;
            defaultKey.SET = new byte[] { 0x20, 0x01 };
            log.Debug(m => m("Change keyentry: {0}", defaultKey));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(defaultKey, authHostDO));
            //auth 0x30
            divKey = //this.getDivKey711("seedWriteKey", keyVer);
                this.byteWorker.Fill(16, 0x00);
            Assert.True(this.samAV2Manager.AuthenticateHost(divKey, 0x30, keyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            // change master
            KeyEntryDO seedMaster = this.dicKeyEntry["seedMasterKey"];
            KeyEntryDO divMaster = new KeyEntryDO
            {
                KeyName = "divMasterKey",
                KeyNo = seedMaster.KeyNo,
                DF_AID = seedMaster.DF_AID,
                DF_KEY_NO = seedMaster.DF_KEY_NO,
                CEK_NO = seedMaster.CEK_NO,
                CEK_VER = seedMaster.CEK_VER,
                KUC = seedMaster.KUC,
                SET = seedMaster.SET, 
                    //new byte[] { 0x20, 0x00 }, // unlock
                ExtSet = seedMaster.ExtSet,
                KeyA = this.getDivKeyIcash("seedMasterKey", "A"),
                KeyB = this.getDivKeyIcash("seedMasterKey", "B"),
                KeyC = this.getDivKeyIcash("seedMasterKey", "C"),
                VerA = seedMaster.VerA,
                VerB = seedMaster.VerB,
                VerC = seedMaster.VerC,
                SamMode = seedMaster.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divMaster));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(divMaster, authHostDO));
            
        }

        [Test]
        public void Test07ChangeIcash2KeyEntryAES()
        {
            byte[] divKey = null;
            byte keyVer = 0x00;
            // unlock sam
            divKey = this.getDivKeyIcash( "seedMasterKey", 0x00 );
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            Assert.True(this.samAV2Manager.AuthenticateHost(divKey, 0x00, keyVer, 0x00, authHostDO));
            log.Debug(m => m("{0}", authHostDO));   
            // change writekey
            KeyEntryDO seedWrite = this.dicKeyEntry["seedWriteKey"];
            KeyEntryDO divWrite = new KeyEntryDO
            {
                KeyName = "divWriteKey",
                KeyNo = seedWrite.KeyNo,
                DF_AID = seedWrite.DF_AID,
                DF_KEY_NO = seedWrite.DF_KEY_NO,
                CEK_NO = seedWrite.CEK_NO,
                CEK_VER = seedWrite.CEK_VER,
                KUC = seedWrite.KUC,
                SET = seedWrite.SET,
                KeyA = this.getDivKey711("seedWriteKey", "A"),
                KeyB = this.getDivKey711("seedWriteKey", "B"),
                KeyC = this.getDivKey711("seedWriteKey", "C"),
                VerA = seedWrite.VerA,
                VerB = seedWrite.VerB,
                VerC = seedWrite.VerC,
                ExtSet = seedWrite.ExtSet,
                SamMode = seedWrite.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divWrite));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(divWrite, authHostDO));
            // change server authentication key 0x31
            KeyEntryDO seedServAuth = this.dicKeyEntry["seedServAuthKey"];
            KeyEntryDO divServAuth = new KeyEntryDO
            {
                KeyName = "divServAuthKey",
                KeyNo = seedServAuth.KeyNo,
                DF_AID = seedServAuth.DF_AID,
                DF_KEY_NO = seedServAuth.DF_KEY_NO,
                CEK_NO = seedServAuth.CEK_NO,
                CEK_VER = seedServAuth.CEK_VER,
                KUC = seedServAuth.KUC,
                SET = seedServAuth.SET,
                KeyA = this.getDivKey711("seedServAuthKey", "A"),
                KeyB = this.getDivKey711("seedServAuthKey", "B"),
                KeyC = this.getDivKey711("seedServAuthKey", "C"),
                VerA = seedServAuth.VerA,
                VerB = seedServAuth.VerB,
                VerC = seedServAuth.VerC,
                ExtSet = seedServAuth.ExtSet,
                SamMode = seedServAuth.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divServAuth));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(divServAuth, authHostDO));
            // change icash2 info key
            KeyEntryDO seedInfo = this.dicKeyEntry["seedInfoKey"];
            log.Debug(m => m("Change keyentry: {0}", seedInfo));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(seedInfo, authHostDO));
            // change payment key
            KeyEntryDO seedPayment = this.dicKeyEntry["seedPaymentKey"];
            log.Debug(m => m("Change keyentry: {0}", seedPayment));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(seedPayment, authHostDO));
            // change charge key
            KeyEntryDO seedCharge = this.dicKeyEntry["seedChargeKey"];
            log.Debug(m => m("Change keyentry: {0}", seedCharge));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(seedCharge, authHostDO));
            // change txlog sign key
            KeyEntryDO seedMac = this.dicKeyEntry["seedMacKey"];
            KeyEntryDO divMac = new KeyEntryDO
            {
                KeyName = "divMacKey",
                KeyNo = seedMac.KeyNo,
                DF_AID = seedMac.DF_AID,
                DF_KEY_NO = seedMac.DF_KEY_NO,
                CEK_NO = seedMac.CEK_NO,
                CEK_VER = seedMac.CEK_VER,
                KUC = seedMac.KUC,
                SET = seedMac.SET,
                KeyA = this.getDivKey711("seedMacKey", "A"),
                KeyB = this.getDivKey711("seedMacKey", "B"),
                KeyC = this.getDivKey711("seedMacKey", "C"),
                VerA = seedMac.VerA,
                VerB = seedMac.VerB,
                VerC = seedMac.VerC,
                ExtSet = seedMac.ExtSet,
                SamMode = seedMac.SamMode
            };
            log.Debug(m => m("Change keyentry: {0}", divMac));
            Assert.True(this.samAV2Manager.ChangeKeyEntryAES(divMac, authHostDO));
        }

        [Test]
        public void Test09AuthenticatePICC()
        {
            byte[] divKey = null;
            byte keyVer = 0x00;
            // unlock sam
            divKey = this.getDivKeyIcash("seedMasterKey", keyVer );
            //Assert.True(this.samAV2Manager.Unlock(divKey, 0x00, 0x01, 0x00));
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            Assert.True(this.samAV2Manager.AuthenticateHost(divKey, 0x00, keyVer, 0x00, authHostDO));
            //
            AuthPICCDO authPICCDO = new AuthPICCDO();
            authPICCDO.Uid = "04322222162980";
            byte[] icash2Uid = this.hexConverter.Hex2Bytes(authPICCDO.Uid);
            divKey = this.getDivKeyIcash("seedPaymentKey", "A", icash2Uid);
            // 
            authPICCDO.KeyNo = 0x33;
            authPICCDO.KeyVer = 0x00;
            authPICCDO.AuthMode = 0x11;
            authPICCDO.RndB = this.hexConverter.Hex2Bytes("C6B6CEB30ADCF817775F2BE2D711F3AF");
            //
            this.aesCryptor.SetIv(SymCryptor.ConstZero);
            this.aesCryptor.SetKey(divKey);
            authPICCDO.EncRndB = this.aesCryptor.Encrypt(authPICCDO.RndB);
            this.aesCryptor.SetIv(authPICCDO.EncRndB); // keep iv
            // check if encRndB ok!
            Assert.AreEqual(this.hexConverter.Hex2Bytes("D4D795A6B4B259F2961369F9C608600A"), authPICCDO.EncRndB);
            //
            authPICCDO.DivInput = this.getDivInputIcash(icash2Uid);
            authPICCDO.EncRndARndBROL8 = this.samAV2Manager.AuthenticatePICC_1(authPICCDO);
            byte[] rndARndBROL8 = this.aesCryptor.Decrypt(authPICCDO.EncRndARndBROL8);
            this.aesCryptor.SetIv(this.byteWorker.SubArray(authPICCDO.EncRndARndBROL8, 16, 16));
            authPICCDO.RndA = this.byteWorker.SubArray(rndARndBROL8, 0, 16);
            Assert.AreEqual(this.byteWorker.RotateLeft(authPICCDO.RndB, 1), this.byteWorker.SubArray(rndARndBROL8, 16, 16));
            authPICCDO.EncRndAROL8 = this.aesCryptor.Encrypt(this.byteWorker.RotateLeft(authPICCDO.RndA, 1));
            bool authOK = this.samAV2Manager.AuthenticatePICC_2(authPICCDO);
            Assert.True(authOK);
        }


        /// <summary>
        //1. SAM_ActivateOfflineKey, P1=0x00( DIV_MODE, no diverse ) Data= 0x3500 ( KNR_KVER ), 將 0x35 keyA 載入
        //2. SAM_LoadInitVector  Data=0xyyyyMMddHHmmss000000000000000000 (設IV)
        //3. SHA1 txlog data, 取前16 bytes, 份為 Data1, Data2 各 8 bytes
        //4. SAM_EncipherOffline_Data P1=0x00, P2=0x00, Data= Data1 || Data1 || Data2 || Data2, 從結果的 idx 16, 取 4 bytes 做 mac
        /// </summary>
        [Test]
        public void Test09Encrypt()
        {
            byte[] divKey = null;
            byte keyVer = 0x00;
            // unlock sam
            divKey = this.getDivKeyIcash( "seedMasterKey", keyVer );
            //Assert.True(this.samAV2Manager.Unlock(divKey, 0x00, 0x01, 0x00));   
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            Assert.True(this.samAV2Manager.AuthenticateHost(divKey, 0x00, keyVer, 0x00, authHostDO));
            
            // transDateTx
            string transDateTxStr = "20150331131600";
            byte[] iv = this.byteWorker.Combine(this.hexConverter.Hex2Bytes(transDateTxStr), this.byteWorker.Fill(9, 0x00));
            string hashDataStr = "CA199CB285437E416304672EE4D721EFACBD3E4D";
            byte[] hashData = this.hexConverter.Hex2Bytes(hashDataStr);
            byte[] decrypted = this.byteWorker.Combine
            (
                this.byteWorker.SubArray(hashData, 0, 8),
                this.byteWorker.SubArray(hashData, 0, 8),
                this.byteWorker.SubArray(hashData, 8, 8),
                this.byteWorker.SubArray(hashData, 8, 8)
            );
            // divMode : 0x00 -> do not diverse
            byte[] result = this.samAV2Manager.Encrypt( 0x35, 0x00, 0x00, iv, decrypted);
            log.Debug(m => m("{0}", this.hexConverter.Bytes2Hex(result)));
            APDULog[] arrayLog = this.samAV2Manager.ApduPlayer.Log.ToArray();
            for (int nI = 0; nI < arrayLog.Length; nI++)
            {
                log.Debug(m => m("{0}", arrayLog[nI]));
            }
            // verify...
            this.aesCryptor.SetIv(iv);
            this.aesCryptor.SetKey(this.getDivKey711("seedMacKey", "A"));
            byte[] expected = this.aesCryptor.Encrypt(decrypted);
            Assert.AreEqual(expected, this.byteWorker.SubArray(result, 0, 32));
        }

        [Test]
        public void Test95ChangeKUCEntryZero()
        {
            KUCDO kUCDO = new KUCDO
            {
                KUCNo = 0x01,
                ProMas = 0xE0,
                RefKeyNo = 0x00,
                RefKeyVer = 0x00, //0x01,
                Limit = 0x00
            };
            // auth default
            //KeyInfo defaultMaster = this.dicKeyInfo["usageKeyDefault"];
            byte keyNo = 0x00;
            byte keyVer = 0x00;
            byte[] keyData = this.getDivKeyIcash("seedMasterKey", 0x00);
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyData, keyNo, keyVer, 0x02, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            this.samAV2Manager.ChangeKUCEntry(kUCDO, authHostDO );
            //
            //Assert.True(this.samAV2Manager.AuthenticateHost(keyData, keyNo, keyVer, 0x00, authHostDO));
            Assert.True(this.samAV2Manager.KillAuthentication( authHostDO ));
            kUCDO = this.samAV2Manager.GetKUCEntry(0x01);
            log.Debug(m => m("After Change: {0}", kUCDO));
        }

        [Test]
        public void Test96ChangeKUCEntryMax()
        {
            KUCDO kUCDO = new KUCDO
            {
                KUCNo = 0x01,
                ProMas = 0xE0,
                RefKeyNo = 0x00,
                RefKeyVer = 0x00,
                Limit = 0xFFFFFFFF
            };
            byte keyNo = 0x00;
            byte keyVer = 0x00;
            byte[] keyData = this.getDivKeyIcash("seedMasterKey", 0x00);
            AuthHostDO authHostDO = new AuthHostDO();
            Assert.True(this.samAV2Manager.AuthenticateHost(keyData, keyNo, keyVer, 0x02, authHostDO));
            log.Debug(m => m("{0}", authHostDO));
            this.samAV2Manager.ChangeKUCEntry(kUCDO, authHostDO);
            //
            //Assert.True(this.samAV2Manager.KillAuthentication( authHostDO ));
            Assert.True(this.samAV2Manager.AuthenticateHost(keyData, keyNo, keyVer, 0x00, authHostDO));
            Assert.True(this.samAV2Manager.KillAuthentication( null ));
            kUCDO = this.samAV2Manager.GetKUCEntry(0x01);
            log.Debug(m => m("After Change: {0}", kUCDO));

        }

        [Test]
        public void Test98GetKUCEntry()
        {
            KUCDO kUCDO = this.samAV2Manager.GetKUCEntry(0x01);
            log.Debug(m => m("{0}", kUCDO));
        }

        [Test]
        public void Test99AuthHostHMAC()
        {
            byte[] divKey = null;
            byte[] uid = this.samAV2Manager.GetUid();
            using (HMACSHA1 hmac = new HMACSHA1(uid))
            {
                // "123456" || 0xffff 
                divKey = this.byteWorker.SubArray
                (
                    hmac.ComputeHash(new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff, 0xff }),
                    0, 16
                );
            }            
            //
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex( uid );
            Assert.True( this.samAV2Manager.AuthenticateHost(divKey, 0x00, 0x00, 0x02, authHostDO) );
            //
            log.Debug(m => m("{0}", authHostDO));
            //
        }

        [Test]
        public void Test99GetKeyEntry()
        {
            for (int i = 0; i < 128; i++) // 0x00 ~ 0xFF
            {
                KeyEntryDO keyEntryDO = this.samAV2Manager.GetKeyEntry((byte)i);
                log.Debug(m => m("{0}", keyEntryDO));
            }
        }

        [Test]
        public void Test99IsAV2Mode()
        {
            Assert.True(this.samAV2Manager.IsAV2Mode());
        }
        

        [TearDown]
        public void TearDown()
        {
            this.samAV2Manager.DisConnect();
        }

        //// sam master key
        //private byte[] getDivInputIcash(byte[] uid)
        //{
        //    return this.byteWorker.Combine
        //    (
        //          uid
        //        , Encoding.ASCII.GetBytes("ICASH")
        //        , uid
        //        , Encoding.ASCII.GetBytes("ICASH")
        //        , uid
        //    );
        //}

        //private byte[] getSeedKey(string seedKeyId)
        //{
        //    byte[] seedKey = null;
        //    if (this.dicKey.ContainsKey(seedKeyId))
        //    {
        //        seedKey = this.hexConverter.Hex2Bytes(this.dicKey[seedKeyId]);
        //    }
        //    else
        //    {
        //        throw new Exception("Seedkey:[" + seedKeyId + "] not found...");
        //    }
        //    return seedKey;
        //}

        //private byte[] getDivKey(string seedKeyId)
        //{
        //    byte[] seedKey = this.getSeedKey(seedKeyId);
        //    byte[] uid = this.samAV2Manager.GetUid();
        //    byte[] divKey = null;
        //    this.keyDeriver.SetSeedKey(seedKey);
        //    this.keyDeriver.DiverseInput(this.getDivInputIcash(uid));
        //    divKey = this.keyDeriver.GetDerivedKey();
        //    log.Debug( m => m( "DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey) ) );
        //    return divKey;
        //}

        // for diverse sam master key and icash2 key
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

        // for management key, authentication key and txlog sign key
        private byte[] getDivInput711(byte[] uid)
        {
            return this.byteWorker.Combine
            (
                //new byte[] { 0x01 }
                new byte[] { 0x86 }, uid
              , new byte[] { 0x53, 0x45, 0x56, 0x45, 0x4E } // "SEVEN"          
              , new byte[] { 0x86 }, uid
              , new byte[] { 0x31, 0x31 } // "11"
              , new byte[] { 0x86 }, uid
            );
        }

        private byte[] getSeedKey(string seedKeyId, string keyVer)
        {
            byte[] seedKey = null;
            if (this.dicKeyEntry.ContainsKey(seedKeyId))
            {
                if( "A".Equals(keyVer) )
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyA;
                }
                else if ("B".Equals(keyVer))
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyB;
                }
                else if ("C".Equals(keyVer))
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyC;
                }
            }
            else
            {
                string errMsg = string.Format("Seedkey:[{0}], Version:[{1}] not found...", seedKeyId, keyVer);
                throw new Exception(errMsg);
            }
            return seedKey;
        }

        private byte[] getSeedKey(string seedKeyId, byte keyVer)
        {
            byte[] seedKey = null;
            if (this.dicKeyEntry.ContainsKey(seedKeyId))
            {
                if( 0x00 == keyVer )
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyA;
                }
                else if( 0x01 == keyVer )
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyB;
                }
                else if( 0x02 == keyVer )
                {
                    seedKey = this.dicKeyEntry[seedKeyId].KeyC;
                }
            }
            else
            {
                string errMsg = string.Format("Seedkey:[{0}], Version:[{1:X2}] not found...", seedKeyId, keyVer);
                throw new Exception(errMsg);
            }
            return seedKey;
        }

        private byte[] getDivKeyIcash(string seedKeyId, string keyVer)
        {
            return this.getDivKeyIcash(seedKeyId, keyVer, null);
        }

        private byte[] getDivKeyIcash(string seedKeyId, byte keyVer)
        {
            return this.getDivKeyIcash(seedKeyId, keyVer, null);
        }

        private byte[] getDivKey711(string seedKeyId, string keyVer)
        {
            return this.getDivKey711(seedKeyId, keyVer, null);
        }

        private byte[] getDivKey711(string seedKeyId, byte keyVer)
        {
            return this.getDivKey711(seedKeyId, keyVer, null);
        }

        private byte[] getDivKey711(string seedKeyId, byte keyVer, byte[] icashUid)
        {
            byte[] seedKey = this.getSeedKey(seedKeyId, keyVer);
            byte[] uid = null;
            if (icashUid == null)
            {
                uid = this.uid;
            }
            else
            {
                uid = icashUid;
            }
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInput711(uid));
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug(m => m("DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey)));
            return divKey;
        }
        private byte[] getDivKey711(string seedKeyId, string keyVer, byte[] icashUid)
        {
            byte[] seedKey = this.getSeedKey(seedKeyId, keyVer);
            byte[] uid = null;
            if (icashUid == null)
            {
                uid = this.uid;
            }
            else
            {
                uid = icashUid;
            }
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInput711(uid));
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug(m => m("DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey)));
            return divKey;
        }

        private byte[] getDivKeyIcash(string seedKeyId, string keyVer, byte[] icashUid)
        {
            byte[] seedKey = this.getSeedKey(seedKeyId, keyVer);
            byte[] uid = null;
            if (icashUid == null)
            {
                uid = this.uid;
            }
            else
            {
                uid = icashUid;
            }
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInputIcash(uid));
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug(m => m("DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey)));
            return divKey;
        }

        private byte[] getDivKeyIcash(string seedKeyId, byte keyVer, byte[] icashUid)
        {
            byte[] seedKey = this.getSeedKey(seedKeyId, keyVer);
            byte[] uid = null;
            if (icashUid == null)
            {
                uid = this.uid;
            }
            else
            {
                uid = icashUid;
            }
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInputIcash(uid));
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug(m => m("DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey)));
            return divKey;
        }

    }
}
