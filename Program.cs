using AlphaOmega.Debug;
using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace SkaterStrFiner
{
    class Program
    {
        #region "Methods to deal with bytes in section" 
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        #endregion

        public static byte[] dataSectionContent = null;

        static void Main(string[] args)
        {
            Console.WriteLine("Skater.net Deobfuscator \n \n");

            int nombreDeStringEncodée = 0;
            ModuleDefMD module = ModuleDefMD.Load(args[0]);
            //Type which contains String Initialization
            TypeDef InitialType = null;
            //We grab native method to count all of them
            List<MethodDef> ListOfNativeMeths = new List<MethodDef>();
            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();
            foreach (TypeDef t in module.GetTypes())
            {
                foreach (MethodDef m in t.Methods)
                {
                    if (m.Name.Contains("OOOOlx"))
                    {
                        ListOfNativeMeths.Add(m);
                    }
                }
            }
            nombreDeStringEncodée = ListOfNativeMeths.Count();
            //We grab the type to find cctor afterwards
            InitialType = ListOfNativeMeths.First().DeclaringType;
            string DLLName = ListOfNativeMeths.First().ImplMap.Module.Name;
            Console.WriteLine("Native DLL Name : " + DLLName);
            //We stock strings in a list
            List<string> deHexedstring = new List<string>();


            //Reading PE
            using (PEFile file = new PEFile(StreamLoader.FromFile(Path.GetDirectoryName(args[0]) + @"\" + DLLName))) 
            {
                var section = file.Header.Sections;
                foreach (var item in section)
                {
                    var realName = new string(item.Name);
                    //Strings are stored in .data section
                    if (realName.Contains(".data"))
                    {
                        //offset of the beginning of the section 
                        var start = item.PointerToRawData;
                        //calculation of section's size
                        var length = item.PointerToRawData + item.SizeOfRawData;

                        //We copy all bytes into a list
                        List<byte> b = new List<byte>();
                        using (FileStream fsSourceDDS = new FileStream(Path.GetDirectoryName(args[0]) + @"\" + DLLName, FileMode.Open, FileAccess.Read))
                        using (BinaryReader binaryReader = new BinaryReader(fsSourceDDS))
                        {
                            fsSourceDDS.Seek(start, SeekOrigin.Begin);
                            while (start < length)
                            {
                                byte y = binaryReader.ReadByte();
                                b.Add(y);
                                start++;
                            }
                        }
                        dataSectionContent = b.ToArray();

                        string input = ByteArrayToString(dataSectionContent);

                        //we split the whole strings
                        string[] datacontent = input.Split(new string[] { "00" }, StringSplitOptions.None);

                        //We remove empty results
                        datacontent = datacontent.Where(x => !string.IsNullOrEmpty(x)).ToArray();


                        //We only need values associated to strings
                        string[] encodedstring = datacontent.Take(nombreDeStringEncodée).Select(i => i.ToString()).ToArray();


                        foreach (var hexedstring in encodedstring)
                        {
                            deHexedstring.Add(Encoding.UTF8.GetString(StringToByteArray(hexedstring)));
                        }
                    }
                }
            }
            //That's why we needed to find the type
            MethodDef cctor = InitialType.FindStaticConstructor();
            if (cctor == null)
            {
                Console.WriteLine("Impossible to find Method which initialize strings");
                return;
            }
            //We make a dictionnary to replace values of field
            Dictionary<FieldDef, string> FieldValue = new Dictionary<FieldDef, string>();
            for (int i = 0; i < cctor.Body.Instructions.Count - 1; i++)
            {
                if (cctor.Body.Instructions[i].OpCode == OpCodes.Ldsfld && cctor.Body.Instructions[i + 1].OpCode == OpCodes.Call && cctor.Body.Instructions[i + 2].OpCode == OpCodes.Stsfld)
                {
                    cctor.Body.Instructions[i].OpCode = OpCodes.Nop;
                    cctor.Body.Instructions[i + 1].OpCode = OpCodes.Ldstr;
                    string decrypted = smethod_0(deHexedstring[0]);
                    cctor.Body.Instructions[i + 1].Operand = decrypted;
                    FieldValue.Add((FieldDef)cctor.Body.Instructions[i + 2].Operand, decrypted);
                    deHexedstring.RemoveAt(0);
                }
            }
            int DecryptedStrings = 0;
            //Replacing field values
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody && method.Body.HasInstructions)
                    {
                        Cleaner(method);
                        for (int i = 0; i < method.Body.Instructions.Count - 1; i++)
                        {
                            try
                            {
                                if (method.Body.Instructions[i].OpCode == OpCodes.Ldsfld)
                                {
                                    FieldDef fld = (FieldDef)method.Body.Instructions[i].Operand;
                                    if (FieldValue.Keys.Contains(fld))
                                    {
                                        method.Body.Instructions[i].OpCode = OpCodes.Ldstr;
                                        method.Body.Instructions[i].Operand = FieldValue[fld];
                                        DecryptedStrings++;
                                    }
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                }
            }
            stopWatch.Stop();
            Console.WriteLine("Done ! Elapsed time : " + stopWatch.Elapsed.TotalSeconds);
            //Saving ASM
            string SavingPath = module.Kind == ModuleKind.Dll ? args[0].Replace(".dll", "-Deobfuscated.dll") : args[0].Replace(".exe", "-Deobfuscated.exe");
            var opts = new ModuleWriterOptions(module);
            opts.MetaDataOptions.Flags = MetaDataFlags.PreserveAll;
            opts.Logger = DummyLogger.NoThrowInstance;
            module.Write(SavingPath, opts);
            Console.WriteLine("Sucessfully decrypted {0} strings", DecryptedStrings);
            Console.WriteLine("Control Flow removed", DecryptedStrings);
            Console.ReadLine();
        }

        //Removing Control Flow 
        public static void Cleaner(MethodDef method)
        {
            BlocksCflowDeobfuscator blocksCflowDeobfuscator = new BlocksCflowDeobfuscator();
            Blocks blocks = new Blocks(method);
            blocksCflowDeobfuscator.Initialize(blocks);
            blocksCflowDeobfuscator.Deobfuscate();
            blocks.RepartitionBlocks();
            IList<Instruction> list;
            IList<ExceptionHandler> exceptionHandlers;
            blocks.GetCode(out list, out exceptionHandlers);
            DotNetUtils.RestoreBody(method, list, exceptionHandlers);
        }

        #region "Skater static string decoding"

        public static string smethod_0(string string_8)
        {
            string text = string.Empty;
            double value = 3.1415;
            string[] array = string_8.Split(new char[]
            {
            ' '
            });
            int num = 0;
            int upperBound = array.GetUpperBound(0);
            checked
            {
                for (int i = num; i <= upperBound; i += 3)
                {
                    if ((double)Convert.ToInt32(array[i + 2]) / (double)Convert.ToInt32(value) == unchecked(11.0 * (double)Convert.ToInt32(value)))
                    {
                        text += char.ConvertFromUtf32(Convert.ToInt32(unchecked(Convert.ToDouble(array[i]) + Convert.ToDouble(255))) * smethod_1(Convert.ToInt32(array[i + 1])));
                    }
                    else
                    {
                        text += char.ConvertFromUtf32(Convert.ToInt32(array[i]) * smethod_1(Convert.ToInt32(array[i + 1])));
                    }
                }
                return text;
            }
        }

        public static int smethod_1(int int_0)
        {
            int result;
            if ((double)int_0 / Convert.ToDouble(2) == (double)Convert.ToInt32((double)int_0 / Convert.ToDouble(2)))
            {
                result = 2;
            }
            else
            {
                result = 1;
            }
            return result;
        }

        #endregion
    }
}
