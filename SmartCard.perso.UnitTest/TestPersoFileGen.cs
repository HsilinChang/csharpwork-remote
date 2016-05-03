using System;
using System.IO;
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
using Kms2.Crypto.Common;
using Kms2.Crypto.Utility;

namespace SmartCard.Perso.UnitTest
{
    [TestFixture]
    public class TestPersoFileGen
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestPersoFileGen));
        //
        private IApplicationContext ctx;        
        private IHexConverter hexConverter;
        private IByteWorker byteWorker;                
        private IDateUtility dateUtility = null;
        private IStrHelper strHelper = null;
        //
        string icash2Orig = null; // @".\Data\2C201407002";
        string icash2File = null;
        string sam2Orig = null;
        string sam2File = null;
        string icash1Orig = null;
        string icash1File = null;
        string sam1Orig = null;
        string sam1File = null;
        string credit1Orig = null;
        string credit1File = null;
        string credit2Orig = null;
        string credit2File = null;
        
        [SetUp]
        public void SetUp()
        {
            this.icash2Orig = @".\Data\2C201407002";
            this.icash2File = @".\Data\2C201407002_New";
            this.sam2Orig = @".\Data\S201407003";
            this.sam2File = @".\Data\S201407003_New";
            this.icash1Orig = @".\Data\C201408001"; // 一代製卡檔
            this.icash1File = @".\Data\C201408001_New";
            this.sam1Orig = @".\Data\M201408002"; // TPLSAM製卡檔
            this.sam1File = @".\Data\M201408002_New";
            this.credit1Orig = @".\Data\L1030800001"; //一代加值製卡檔，加值123元
            this.credit1File = @".\Data\L1030800001_New";
            this.credit2Orig = @".\Data\2L1030800002";
            this.credit2File = @".\Data\2L1030800002_New";
            //
            this.ctx = ContextRegistry.GetContext();
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;            
            this.dateUtility = ctx["dateUtility"] as IDateUtility;
            this.strHelper = ctx["strHelper"] as IStrHelper;
        }

        [Test]
        public void Test01SAMAV2Gen()
        {
            using (Stream sr = new FileStream(this.sam2Orig, FileMode.Open))
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                using (Stream sw = new FileStream(this.sam2File, FileMode.Create))
                {
                    int offSet = 0;
                    sw.Write(buf, offSet, 195);
                    offSet += 195;
                    byte[] emBytes = Encoding.ASCII.GetBytes( "0000055");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    sw.Write(buf, offSet, 4);
                    offSet += 4;
                    emBytes = new byte[] { 0x00, 0x30, 0x00, 0x19 };
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    // 23->25 "icashcorp_ICashIISAMPerso"
                    emBytes = Encoding.ASCII.GetBytes("icashcorp_ICashIISAMPerso");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += 23;
                    //                    
                    emBytes = new byte[] { 0x00, 0x13 };
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += 2;
                    byte[] sp8 = this.byteWorker.Fill(8, 0x20);
                    sw.Write(sp8, 0, sp8.Length);
                    offSet += 8;
                    byte[] setExt = Encoding.ASCII.GetBytes("2004");
                    sw.Write(setExt, 0, setExt.Length);
                    //offSet += setExt.Length; // new insert
                    byte[] one7 = this.byteWorker.Fill(7, 0x31);
                    sw.Write(one7, 0, one7.Length);
                    offSet += 7;
                    sw.Write(buf, offSet, 6);
                }
            }                
        }


        [Test]
        public void Test03Icash2Gen()
        {
            using(  Stream sr = new FileStream( this.icash2Orig, FileMode.Open ) )
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                using( Stream sw = new FileStream( this.icash2File, FileMode.Create ) )
                {
                    int offSet = 0;
                    sw.Write(buf, offSet, 93);
                    offSet += 93;
                    //
                    byte[] emBytes = Encoding.ASCII.GetBytes("0001559");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    sw.Write(buf, offSet, 4);
                    offSet += 4;
                    //
                    emBytes = new byte[] { 0x00, 0x00, 0x06, 0x0E };
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    emBytes = new byte[] { 0x00, 0x16 };
                    sw.Write(emBytes, 0, emBytes.Length);                    
                    offSet += 22;
                    //
                    emBytes = Encoding.ASCII.GetBytes( "icashcorp_ICashIIPerso" );
                    sw.Write(emBytes, 0, emBytes.Length);
                    //offSet += emBytes.Length;
                    //
                    emBytes = new byte[] { 0x00,0x00,0x05,0xF2 };
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //  
                    sw.Write(buf, offSet, 18);
                    offSet += 18;
                    //
                    byte[] fmtVer = Encoding.ASCII.GetBytes("0002");
                    sw.Write(fmtVer, 0, fmtVer.Length);
                    offSet += 4;
                    // 94 = 32 + 12 + 24 + 26 //50 // 62
                    sw.Write(buf, offSet, 32);
                    offSet += 32;
                    //
                    emBytes = this.byteWorker.Fill(12, 0x41);
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    emBytes = this.byteWorker.Fill(24, 0x42);
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    //emBytes = this.byteWorker.Fill(24, 0x43);
                    //sw.Write(emBytes, 0, emBytes.Length);
                    //offSet += emBytes.Length;
                    //
                    emBytes = this.byteWorker.Fill(8, 0x31);
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    emBytes = this.byteWorker.Fill(8, 0x32);
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    emBytes = this.byteWorker.Fill(8, 0x33);
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    emBytes = Encoding.ASCII.GetBytes("01");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    byte[] neg = Encoding.ASCII.GetBytes( "9CFFFFFF" );
                    sw.Write(neg, 0, neg.Length);
                    //
                    sw.Write(buf, offSet, 20);
                    offSet += 20;
                    //
                    byte[] rfu = Encoding.ASCII.GetBytes( this.hexConverter.Bytes2Hex( this.byteWorker.Fill(96, 0x11) ) );
                    sw.Write(rfu, 0, rfu.Length);
                    rfu = Encoding.ASCII.GetBytes(this.hexConverter.Bytes2Hex(this.byteWorker.Fill(96, 0x12)));
                    sw.Write(rfu, 0, rfu.Length);
                    //
                    sw.Write(buf, offSet, 34);
                    offSet += 34;
                    //
                    rfu = Encoding.ASCII.GetBytes(this.hexConverter.Bytes2Hex(this.byteWorker.Fill(96, 0x15)));
                    sw.Write(rfu, 0, rfu.Length);
                    rfu = Encoding.ASCII.GetBytes(this.hexConverter.Bytes2Hex(this.byteWorker.Fill(96, 0x16)));
                    sw.Write(rfu, 0, rfu.Length);
                    //
                    rfu = Encoding.ASCII.GetBytes(this.hexConverter.Bytes2Hex(this.byteWorker.Fill(96, 0x1D)));
                    sw.Write(rfu, 0, rfu.Length);
                    rfu = Encoding.ASCII.GetBytes(this.hexConverter.Bytes2Hex(this.byteWorker.Fill(96, 0x1E)));
                    sw.Write(rfu, 0, rfu.Length);
                    rfu = Encoding.ASCII.GetBytes(this.hexConverter.Bytes2Hex(this.byteWorker.Fill(96, 0x1F)));
                    sw.Write(rfu, 0, rfu.Length);
                    //
                    sw.Write(buf, offSet, 6);
                    offSet += 6;
                }
            }                
        }

        [Test]
        public void Test04Icash2Valid()
        {
            using (Stream sr = new FileStream(this.icash2File, FileMode.Open))
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                byte[] data = this.byteWorker.SubArray(buf, 0, cntRead);
                log.Debug( this.hexConverter.Bytes2Hex( data ) );
            }
        }

        [Test]
        public void Test02SAM2Valid()
        {
            using (Stream sr = new FileStream(this.sam2File, FileMode.Open))
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                byte[] data = this.byteWorker.SubArray(buf, 0, cntRead);
                log.Debug(this.hexConverter.Bytes2Hex(data));
            }
        }

        [Test]
        public void Test05Icash1Gen()
        {
            using (Stream sr = new FileStream(this.icash1Orig, FileMode.Open))
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                using (Stream sw = new FileStream(this.icash1File, FileMode.Create))
                {
                    int offSet = 0;
                    sw.Write(buf, offSet, 7);
                    offSet += 7;
                    //
                    byte[] emBytes = Encoding.ASCII.GetBytes("0000092");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    sw.Write(buf, offSet, 73);
                    offSet += 73;
                    //
                    emBytes = Encoding.ASCII.GetBytes("7101130011691009");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += 12;
                    //
                    sw.Write(buf, offSet, cntRead - offSet);
                }
            }
        }

        [Test]
        public void Test07Sam1Gen()
        {
            using (Stream sr = new FileStream(this.sam1Orig, FileMode.Open))
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                using (Stream sw = new FileStream(this.sam1File, FileMode.Create))
                {
                    int offSet = 0;
                    sw.Write(buf, offSet, 83);
                    offSet += 83;
                    //
                    byte[] emBytes = Encoding.ASCII.GetBytes("5");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    sw.Write(buf, offSet, 5);
                    offSet += 5;
                    //
                    emBytes = new byte[] { 0x8A,0x00,0x15 };
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    // 19 -> 21"icashcorp_TPLSAMPerso
                    emBytes = Encoding.ASCII.GetBytes("icashcorp_TPLSAMPerso");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += 19;
                    //
                    sw.Write(buf, offSet, cntRead - offSet);
                }
            }
        }

        [Test]
        public void Test09SVC1Gen()
        {
            using (Stream sr = new FileStream(this.credit1Orig, FileMode.Open))
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                using (Stream sw = new FileStream(this.credit1File, FileMode.Create))
                {
                    int offSet = 0;
                    sw.Write(buf, offSet, 7);
                    offSet += 7;
                    //
                    byte[] emBytes = Encoding.ASCII.GetBytes("0000112");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    sw.Write(buf, offSet, 4);
                    offSet += 4;
                    //
                    emBytes = new byte[] { 0x00, 0x6A, 0x00, 0x11 };
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //                    
                    // 12 -> 17 "icashcorp_SVCLoad"
                    emBytes = Encoding.ASCII.GetBytes("icashcorp_SVCLoad");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += 12;
                    //
                    sw.Write(buf, offSet, cntRead - offSet);
                }
            }
        }

        [Test]
        public void Test11SVC2Gen()
        {
            using (Stream sr = new FileStream(this.credit2Orig, FileMode.Open))
            {
                byte[] buf = new byte[1024];
                int cntRead = sr.Read(buf, 0, buf.Length);
                log.Debug(cntRead);
                using (Stream sw = new FileStream(this.credit2File, FileMode.Create))
                {
                    int offSet = 0;
                    sw.Write(buf, offSet, 7);
                    offSet += 7;
                    //
                    byte[] emBytes = Encoding.ASCII.GetBytes("0000080");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //
                    sw.Write(buf, offSet, 4);
                    offSet += 4;
                    //
                    emBytes = new byte[] { 0x00, 0x00, 0x00, 0x47, 0x00, 0x15 };
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += emBytes.Length;
                    //                    
                    // 19 -> 21 "icashcorp_SVCLoad"
                    emBytes = Encoding.ASCII.GetBytes("icashcorp_ICashIILoad");
                    sw.Write(emBytes, 0, emBytes.Length);
                    offSet += 19;
                    //
                    sw.Write(buf, offSet, cntRead - offSet);
                }
            }
        }

        [TearDown]
        public void TearDown()
        {

        }
    }
}
