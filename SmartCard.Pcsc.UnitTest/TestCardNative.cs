using System;
using System.Runtime.InteropServices;
using System.Threading;
//
using Spring.Context;
using Spring.Context.Support;
using Common.Logging;
//
using NUnit.Framework;
//
using SmartCard.Pcsc;
using Kms2.Crypto.Common;

namespace SmartCard.Pcsc.UnitTest
{
    [TestFixture]
    public class TestCardNative
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(TestCardNative));
        ICard cardNative = null;
        //
        private IApplicationContext ctx;
        IHexConverter hexConverter = null;
        IByteWorker byteWorker = null;

        [SetUp]
        public void InitContext()
        {
            this.ctx = ContextRegistry.GetContext();
            this.hexConverter = ctx["hexConverter"] as IHexConverter;
            this.cardNative = ctx["cardNative"] as ICard;
            this.byteWorker = ctx["byteWorker"] as IByteWorker;
        }

        [Test]
        public void Test01ListReaders()
        {
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
            }
            else
            {
                log.Debug("List Available readers...");
                foreach (string reader in readers)
                {
                    log.Debug(reader);
                }
            }
        }

        [Test]
        public void Test02Connect()
        {
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            //
            ICard cad = null;
            foreach (string reader in readers)
            {
                try
                {
                    cad = ctx["cardNative"] as ICard;
                    log.Debug("Connect reader:[" + reader + "]....");
                    cad.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                    // Get the ATR of the card
                    byte[] atrValue = cad.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                    log.Debug("ATR:[" + this.hexConverter.Bytes2Hex(atrValue) + "]");
                    cad.Disconnect(DISCONNECT.Unpower);
                }
                catch (Exception ex)
                {
                    log.Error(ex.Message);
                }
            }
        }

        [Test]
        public void Test03CardDetection()
        {
            // get first reader...
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            // 
            ICard[] cads = new CardNative[readers.Length];
            for (int i = 0; i < readers.Length; i++)
            {
                CardNative cad = (CardNative)(ctx["cardNative"] as ICard);
                cads[i] = cad;
                int j = i;
                cad.OnCardInserted +=
                (x) =>
                {
                    log.Debug(readers[j] + ": Card inserted....");
                }
                ;
                cad.OnCardRemoved +=
                (x) =>
                {
                    log.Debug(readers[j] + ": Card removed....");
                }
                ;
                cad.StartCardEvents(readers[i]);
            }
            log.Debug("Test card status for 20 secs...");
            Thread.Sleep(20000);
            for (int i = 0; i < cads.Length; i++)
            {
                ((CardNative)cads[i]).StopCardEvents();
            }
        }

        [Test]
        public void Test04Transmit()
        {
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }

            foreach (string reader in readers)
            {
                if (!(reader.StartsWith("CASTLES EZ710BU_CL") || reader.StartsWith("SCM Microsystems SCL3711 reader & NFC device") || reader.StartsWith("NXP PR533")))
                {
                    log.Debug("Skip: [" + reader + "]....");
                    continue;
                }
                log.Debug(String.Format("Connect:[{0}]...", reader));
                this.cardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);
                // get uid from mifare card
                APDUCommand cmd = new APDUCommand
                (
                    0xff
                  , 0xca
                  , 0x00
                  , 0x00
                  , null
                  , new byte[] { 0x00 }
               );
                log.Debug(cmd);
                APDUResponse response = this.cardNative.Transmit(cmd);
                log.Debug(response);
                // disconnect...
                this.cardNative.Disconnect(DISCONNECT.Unpower);
            }
        }

        [Test]
        public void Test05GetVersion()
        {
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            foreach (string reader in readers)
            {
                if (!(reader.StartsWith("CASTLES EZ710BU_CL") || reader.StartsWith("SCM Microsystems SCL3711 reader & NFC device") || reader.StartsWith("NXP PR533")))
                {
                    log.Debug("Skip: [" + reader + "]....");
                    continue;
                }
                try
                {
                    log.Debug("Connect: [" + reader + "]....");
                    this.cardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);

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
                    Assert.True((response.SW1 == 0x91) && (response.SW2 == 0xAF));
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
                        Assert.True(response.SW1 == 0x91);
                        if ((response.SW1 == 0x91) && (response.SW2 == 0x00))
                        {
                            log.Debug("UID:[" + this.hexConverter.Bytes2Hex(this.byteWorker.SubArray(response.Data, 0, 7)) + "]");
                        }
                    }
                }
                catch (Exception ex)
                {
                    log.Error(ex.Message);
                }
                // disconnect...
                this.cardNative.Disconnect(DISCONNECT.Unpower);
            }
        }

        //[Test]
        public void Test06List9501()
        {
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            foreach (string reader in readers)
            {
                log.Debug("Connect: [" + reader + "]....");
                this.cardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);

                APDUCommand cmd = new APDUCommand
                (
                    //00A40100023F00
                    0x00
                  , 0xA4
                  , 0x01
                  , 0x00
                  , new byte[] { 0x3F, 0x00 }
                );
                log.Debug(cmd);

                APDUResponse response = this.cardNative.Transmit(cmd);
                log.Debug(response);

                cmd = new APDUCommand
                (
                    //00A40100029501
                    0x00
                  , 0xA4
                  , 0x01
                  , 0x00
                  , new byte[] { 0x95, 0x01 }
                );
                log.Debug(cmd);

                response = this.cardNative.Transmit(cmd);

                log.Debug(response);
                Assert.True((response.SW1 == 0x90) && (response.SW2 == 0x00));
                {
                    cmd = new APDUCommand
                    (
                        0x00
                      , 0xAA
                      , 0x00
                      , 0x00
                      , null
                      , new byte[] { 0x00, 0x00, 00 }  // extended le (3)
                    );
                    log.Debug(cmd);

                    response = this.cardNative.Transmit(cmd);

                    log.Debug(response);
                }

                Assert.True((response.SW1 == 0x90) && (response.SW2 == 0x00));

                // disconnect...
                this.cardNative.Disconnect(DISCONNECT.Unpower);
            }
        }

        //[Test]
        public void Test06List9503()
        {
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            foreach (string reader in readers)
            {
                log.Debug("Connect: [" + reader + "]....");
                this.cardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);

                APDUCommand cmd = new APDUCommand
                (
                    //00A40100023F00
                    0x00
                  , 0xA4
                  , 0x01
                  , 0x00
                  , new byte[] { 0x3F, 0x00 }
                );
                log.Debug(cmd);

                APDUResponse response = this.cardNative.Transmit(cmd);
                log.Debug(response);

                cmd = new APDUCommand
                (
                    //00A40100029501
                    0x00
                  , 0xA4
                  , 0x01
                  , 0x00
                  , new byte[] { 0x95, 0x03 }
                );
                log.Debug(cmd);

                response = this.cardNative.Transmit(cmd);

                log.Debug(response);
                Assert.True((response.SW1 == 0x90) && (response.SW2 == 0x00));
                {
                    cmd = new APDUCommand
                    (
                        0x00
                      , 0xAA
                      , 0x00
                      , 0x00
                      , null
                      , new byte[] { 0x00, 0x00, 00 }  // extended le (3)
                    );
                    log.Debug(cmd);

                    response = this.cardNative.Transmit(cmd);

                    log.Debug(response);
                }

                Assert.True((response.SW1 == 0x90) && (response.SW2 == 0x00));

                // disconnect...
                this.cardNative.Disconnect(DISCONNECT.Unpower);
            }
        }

        [Test]
        public void Test07List3F00()
        {
            string[] readers = this.cardNative.ListReaders();
            if (readers == null)
            {
                log.Debug("No reader exists!");
                return;
            }
            foreach (string reader in readers)
            {
                if (!(reader.StartsWith("CASTLES EZ100PU") || reader.StartsWith("Generic EMV Smartcard Reader")))
                {
                    log.Debug("Skip: [" + reader + "]....");
                    continue;
                }
                //
                try
                {
                    log.Debug("Connect: [" + reader + "]....");
                    this.cardNative.Connect(reader, SHARE.Shared, PROTOCOL.T0orT1);

                    APDUCommand cmd = new APDUCommand
                    (
                        //00A40100023F00
                        0x00
                      , 0xA4
                      , 0x01
                      , 0x00
                      , new byte[] { 0x3F, 0x00 }
                    );
                    log.Debug(cmd);

                    APDUResponse response = this.cardNative.Transmit(cmd);
                    log.Debug(response);

                    Assert.True((response.SW1 == 0x90) && (response.SW2 == 0x00));
                    {
                        cmd = new APDUCommand
                        (
                            0x00
                          , 0xAA
                          , 0x00
                          , 0x00
                          , null
                          , new byte[] { 0x00, 0x00, 00 }  // extended le (3)
                        );
                        log.Debug(cmd);

                        response = this.cardNative.Transmit(cmd);

                        log.Debug(response);
                    }

                    Assert.True((response.SW1 == 0x90) && (response.SW2 == 0x00));

                    // disconnect...
                    this.cardNative.Disconnect(DISCONNECT.Unpower);
                }
                catch (Exception ex)
                {
                    log.Error(ex.Message);
                }
            }
        }

        [TearDown]
        public void TearDown()
        {
            this.cardNative = null;
        }
    }
}
