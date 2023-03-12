using AgileUnpacker.Core;
using AgileUnpacker.Protections;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AgileUnpacker {
    internal class Program {
        static void Main(string[] args) {
            Console.Clear();
            Context context = new Context(args[0]);
            Console.WriteLine("Processing: " + context.Module.Name);
            new RestoreCalls().Execute(context);
            new StringEncryption().Execute(context);
            new ResourceEncryption().Execute(context);
            context.Save();
            Console.WriteLine("==================");
            Console.WriteLine("File saved in : " + context.output);
            Console.WriteLine("Press enter to exit...");
            Console.ReadLine();
            Environment.Exit(0);
        }
    }
}
