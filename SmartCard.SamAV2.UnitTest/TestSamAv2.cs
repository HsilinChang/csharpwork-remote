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
        private ISamManager samAV2Manager = null;
        private IHexConverter hexConverter = null;
        private IByteWorker byteWorker = null;
        private IKeyDeriver keyDeriver;
        private byte[] uid = null;
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
        private IDictionary<string, string> dicKey = new Dictionary<string, string>()
		{
           { "seed00CMKHex",       "4631317770440EDA46E875C974ADE505" }
           // { "seed00CMKHex",       "75738D8D534FB7EB719DFB749E750428" }
           // { "seed00CMKHex",       "CDD222333ED33527BA289AC6841B210C" }
           ,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }
            //,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }
            //,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }

           //,{ "seed30KeyMasterHex", "98AE6B9684B4700E3042AF03E00ADB56" }
           //,{ "seed31SvrAuthHex",   "5C9A1031BE73561663B393DBFEFDEE5A" }
           //,{ "seed35TxLogMacHex",  "A672F20A9062B8FD00D0A592846E881C" }
		}
        ;
        
        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
            this.keyDeriver = ctx["aes128KeyDeriver"] as IKeyDeriver;
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
                    SamMode = "AV1"
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
                    SET = new byte[] { 0x00, 0x00 },
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
            this.samAV2Manager = ctx["samAV2Manager"] as ISamManager;
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
            // change master to icash master
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
                KeyA = this.getDivKeyIcash("seedMasterKey", "A"),
                KeyB = this.getDivKeyIcash("seedMasterKey", "B"),
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
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            byte[] keyData = this.getDivKeyIcash("seedMasterKey", "B");
            Assert.True(this.samAV2Manager.AuthenticateHostAES( keyData, 0x00, 0x01, 0x00, authHostDO ));
            log.Debug(authHostDO);
        }

        [Test]
        public void Test05Switch2AV2Mode()
        {
            byte keyVer = 0x01;     // key B        
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            byte[] keyData = this.getDivKeyIcash("seedMasterKey", "B");
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
        public void Test07AuthenticateHost()
        {
            byte[] divKey = this.getDivKeyIcash("seedMasterKey", "A");
            AuthHostDO authHostDO = new AuthHostDO();
            authHostDO.Uid = this.hexConverter.Bytes2Hex(this.uid);
            Assert.True( this.samAV2Manager.AuthenticateHost(divKey, 0x00, 0x00, 0x00, authHostDO ));
            log.Debug(m => m("{0}", authHostDO));
        }

        [Test]
        public void Test99AuthHost()
        {
            byte[] divKey = null;
            byte[] uid = this.samAV2Manager.GetUid();
            using (HMACSHA1 hmac = new HMACSHA1(uid))
            {
                divKey = 
                    this.byteWorker.SubArray
                    (
                        hmac.ComputeHash(new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff, 0xff }), 0, 16
                    );
            }            

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
            byte[] uid = this.samAV2Manager.GetUid();
            byte[] divKey = null;
            this.keyDeriver.SetSeedKey(seedKey);
            this.keyDeriver.DiverseInput(this.getDivInputIcash(uid));
            divKey = this.keyDeriver.GetDerivedKey();
            log.Debug( m => m( "DiverseKey:[{0}]", this.hexConverter.Bytes2Hex(divKey) ) );
            return divKey;
        }

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
                if ("A".Equals(keyVer))
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

        private byte[] getDivKeyIcash(string seedKeyId, string keyVer)
        {
            return this.getDivKeyIcash(seedKeyId, keyVer, null);
        }

        private byte[] getDivKey711(string seedKeyId, string keyVer)
        {
            return this.getDivKey711(seedKeyId, keyVer, null);
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

    }
}
