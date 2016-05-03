using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
//
using Spring.Context;
using Spring.Context.Support;

namespace SmartCard.ValidSam
{
    static class Program
    {
        public static IApplicationContext ctx;
        /// <summary>
        /// 應用程式的主要進入點。
        /// </summary>
        [STAThread]
        static void Main()
        {            
            ctx = ContextRegistry.GetContext();
            //
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }
    }
}
