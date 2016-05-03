using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
// 
using System.IO;
using SmartCard.SamAV2;
using Kms2.Crypto.Common;
using Common.Logging;

namespace SmartCard.ValidSam
{
    public partial class Form1 : Form
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Form1));
        public Form1()
        {
            InitializeComponent();
        }


        private void button1_Click(object sender, EventArgs e)
        {

            // 開檔對話盒:
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.Filter = @"KeyCard|*.dat";
            openFileDialog1.Title = "Open Key Card";
            openFileDialog1.RestoreDirectory = true;
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                string keyCardPath = openFileDialog1.FileName.ToString();
                // set key card
                showMessage( string.Format( "Open Key Card: [{0}]", keyCardPath ), false );
                IMkSessionManager mkSessionManager = Program.ctx["mkSessionManager"] as IMkSessionManager;
                if (mkSessionManager.SetKeyCard(keyCardPath))
                {
                    showMessage( "Key Card Load OK!", true );
                }
                else
                {
                    showMessage( "Key Card Load Fail!", true );
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            // 開檔對話盒:
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.Filter = @"KeyFile|*.dat";
            openFileDialog1.Title = "Open Key File";
            openFileDialog1.RestoreDirectory = true;
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                string keyFilePath = openFileDialog1.FileName.ToString();
                showMessage( string.Format( "Open Key File: [{0}]", keyFilePath ), false );
                // set key card
                IMkSessionManager mkSessionManager = Program.ctx["mkSessionManager"] as IMkSessionManager;
                if (mkSessionManager.SetKeyFile(keyFilePath))
                {
                    showMessage("Key File Load OK!", true );
                }
                else
                {
                    showMessage("Key File Load Fail!", true );
                }
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            IMkSessionManager mkSessionManager = Program.ctx["mkSessionManager"] as IMkSessionManager;
            ISamManager samAV2Manager = Program.ctx["samAV2Manager"] as ISamManager;
            IHexConverter hexConverter = Program.ctx["hexConverter"] as IHexConverter;
            try
            {
                if( !samAV2Manager.Connect())
                {
                    //try
                    //{
                    //    samAV2Manager.DisConnect();
                    //}
                    //catch (Exception ex1)
                    //{
                    //    log.Error(m => m("{0}", ex1.StackTrace));
                    //}
                    showMessage( "Fail! Can't Connect SAM, Pls. Replug and Try again...", true );
                    return;
                }
                byte[] uid = samAV2Manager.GetUid();
                //showMessage(string.Format("SAM UID: [{0}]...", hexConverter.Bytes2Hex(uid)), false);
                byte[] mk = mkSessionManager.GetMasterKey(uid);
                if (null == mk)
                {
                    showMessage( string.Format( "Fail! UID:[{0}] Master Key Not Found...", hexConverter.Bytes2Hex(uid) ), true);
                    //samAV2Manager.DisConnect();
                }
                else
                {
                    bool result = samAV2Manager.Unlock(mk, 0x00, 0x00, 0x00);
                    //samAV2Manager.DisConnect();
                    if (result)
                    {
                        showMessage( string.Format( "Pass! UID:[{0}] Unlock OK...", hexConverter.Bytes2Hex(uid) ), true);
                    }
                    else
                    {
                        showMessage( string.Format( "Fail! UID:[{0}] Unlock Fail...", hexConverter.Bytes2Hex(uid) ), true );
                    }
                }
            }
            catch( Exception ex )
            {
                log.Error(m => m("{0}", ex.StackTrace));
                showMessage("Fail! Read SAM Fail, Pls. Replug...", true);
            }
            finally
            {
                try
                {
                    samAV2Manager.DisConnect();
                }
                catch (Exception ex1)
                {
                    log.Error(m => m("{0}", ex1.StackTrace));
                }
            }
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void showMessage( string msg , bool showBox )
        {
            log.Debug(m => m("{0}", msg));
            textBox1.Text += ( msg + "\r\n" );
            if (showBox)
            {
                MessageBox.Show(msg);
            }
        }
    }
}
