using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Metadata.Tables;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace AgileUnpacker.Core {
    internal class Context {
        public ModuleDefinition Module;
        public Assembly Asm;
        public string output;
        public Context(string path) {
            Module = ModuleDefinition.FromFile(path);
            output = path.Replace(Path.GetExtension(path), $"_unpacked{Path.GetExtension(path)}");
            Asm = Assembly.LoadFrom(path);
        }
        public void Save() => Module.Write(output);


        public TypeDefinition StringDecryptorType;
        public MetadataToken StringMDToken;
    }
}
