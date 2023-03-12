using AgileUnpacker.Core;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AgileUnpacker.Protections {
    internal class ResourceEncryption : Protection {
        public override string Name => nameof(ResourceEncryption);

        public override void Execute(Context context) {
            var module = context.Module;
            var moduleCctor = module.GetModuleConstructor();
            var instrs = moduleCctor.CilMethodBody.Instructions;
            var calls = instrs.Where(x => x.OpCode == CilOpCodes.Call && x.Operand is MethodDefinition);
            Console.WriteLine("Looking for resource encryption type...");
            MethodDefinition setupDecryptMethod = null;
            TypeDefinition decryptType = null;
            CilInstruction instr = null;
            foreach(var call in calls) {
                var methodDef = call.Operand as MethodDefinition;
                var callToEventHandler = methodDef.CilMethodBody.Instructions.First(x => x.OpCode == CilOpCodes.Ldftn);
                if(callToEventHandler.Operand is MethodDefinition evenHandler) {
                    if(evenHandler.Signature.ReturnType.IsTypeOf("System.Reflection", "Assembly")) {
                        setupDecryptMethod = methodDef;
                        decryptType = methodDef.DeclaringType;
                        instr = call;
                        Console.WriteLine($"Found resource decryptor\n Name: {decryptType.Name}\n Token: {decryptType.MetadataToken.ToInt32()}");
                    }

                }

            }
            if(instr != null) {
                instrs.Remove(instr);
            }
            if(decryptType != null) {

                Console.WriteLine("Looking for encrypted resources");
                string resourceName = "";
                foreach(var method in decryptType.Methods) {
                    if(method.Parameters.Count == 2) {
                        var strings = method.CilMethodBody.Instructions.First(x => x.OpCode == CilOpCodes.Ldstr && x.Operand.ToString() != "RequestingAssembly");
                        if(module.Resources.Any(x => x.Name == strings.Operand.ToString())) {
                            resourceName = strings.Operand.ToString();
                            Console.WriteLine("Found encrypted resources");
                            break;
                        }
                    }
                }
                if(!string.IsNullOrEmpty(resourceName)) {
                    var resource = module.Resources.First(x => x.Name == resourceName);
                    var decrypted = decryptStream(new MemoryStream(resource.GetData()));
                    var resourceModule = ModuleDefinition.FromBytes(decrypted);
                    foreach(var rsrc in resourceModule.Resources) {
                        var newResource = new ManifestResource(rsrc.Name, rsrc.Attributes, new DataSegment(rsrc.GetData()));
                        module.Resources.Add(newResource);
                        Console.WriteLine($"Restored resource `{rsrc.Name}`");
                    }
                    module.Resources.Remove(resource);
                    Console.WriteLine($"Restored {resourceModule.Resources.Count} resources");
                    module.TopLevelTypes.Remove(decryptType);
                }
            }
        }
        private static byte[] decryptStream(Stream resourceStream) {
            BinaryReader binaryReader = new BinaryReader(resourceStream);
            string text = binaryReader.ReadString();
            byte[] array = binaryReader.ReadBytes((int)(resourceStream.Length - resourceStream.Position));
            ICryptoTransform cryptoTransform = new DESCryptoServiceProvider {
                Key = Encoding.ASCII.GetBytes(text),
                IV = Encoding.ASCII.GetBytes(text)
            }.CreateDecryptor();
            MemoryStream memoryStream = new MemoryStream(array);
            return new BinaryReader(new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read)).ReadBytes((int)memoryStream.Length);
        }
    }
}
