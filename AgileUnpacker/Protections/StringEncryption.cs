using AgileUnpacker.Core;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AgileUnpacker.Protections {
    internal class StringEncryption : Protection {
        public override string Name => nameof(StringEncryption);

        public override void Execute(Context context) {
            var module = context.Module;
            Console.WriteLine("Looking for string decryptor type...");
            foreach(var type in module.TopLevelTypes) {
                if(isStringDecryptorType(type)) {
                    context.StringDecryptorType = type;
                    Console.WriteLine($"Found string decrytor type\n Name: {type.Name}\n Token: {type.MetadataToken.ToInt32()}");
                    Console.WriteLine("Looking for string decryptor method...");
                    foreach(var method in type.Methods) {
                        if(!method.IsConstructor) {
                            if(method.IsStatic) {
                                if(method.Parameters[0].ParameterType == module.CorLibTypeFactory.String) {
                                    var instrs = method.CilMethodBody.Instructions;
                                    if(instrs.First(x => x.OpCode == CilOpCodes.Ldsfld).Operand.ToString().Contains("Hashtable")) {
                                        Console.WriteLine($"Found string decryptor method\n Name: {method.Name}\n Token: {type.MetadataToken.ToInt32()}");
                                        context.StringMDToken = method.MetadataToken;
                                        break;
                                    }

                                }
                            }
                        }
                    }
                    if(context.StringMDToken != null) {
                        break;
                    }
                }

            }

            if(context.StringDecryptorType != null) {

                Console.WriteLine("Decrypting strings...");
                var stringDecryptMethod = context.Asm.ManifestModule.ResolveMethod(context.StringMDToken.ToInt32());
                foreach(var type in module.TopLevelTypes) {
                    if(type == context.StringDecryptorType)
                        continue;
                    foreach(var method in type.Methods.Where(x => x.CilMethodBody != null)) {
                        var instrs = method.CilMethodBody.Instructions;
                        for(int i = 0; i < instrs.Count; i++) {
                            var instr = instrs[i];
                            if(instr.OpCode != CilOpCodes.Call)
                                continue;
                            var call = instr.Operand;
                            if(instr.Operand is MethodDefinition methodDef) {
                                if(methodDef.MetadataToken == context.StringMDToken) {
                                    encryptedStringsCount++;
                                    var str = instrs[i - 1];
                                    try {
                                        var decryptedString = (string)stringDecryptMethod.Invoke(null, new object[] { str.Operand.ToString() });
                                        decryptedStringsCount++;
                                        str.ReplaceWithNop();
                                        instr.ReplaceWith(CilOpCodes.Ldstr, decryptedString);
                                    } catch { }
                                }
                            }
                        }
                    }
                }
            }

            Console.WriteLine($"Finished string encryption\n Decrypted {decryptedStringsCount} out of {encryptedStringsCount}");
            if(decryptedStringsCount == encryptedStringsCount) {
                module.TopLevelTypes.Remove(context.StringDecryptorType);
            }
        }



        private bool isStringDecryptorType(TypeDefinition type) {
            int detections = 0;
            if(type.CustomAttributes.Any(x => x.ToString().Contains("SecuritySafeCritical"))) {
                var constructor = type.GetStaticConstructor();
                var instrs = constructor.CilMethodBody.Instructions;
                if(instrs[0].Operand.ToString().Contains("Hashtable"))
                    detections++;
                if(instrs[3].OpCode == CilOpCodes.Newarr && instrs[3].Operand.ToString().Contains("Byte"))
                    detections++;

            }
            return detections > 0;
        }

        private int encryptedStringsCount = 0;
        private int decryptedStringsCount = 0;

    }
}
