/* ###
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dragonfang;

import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public abstract class AbstractDragonFangTest extends AbstractGhidraHeadlessIntegrationTest
{

    protected static final String SIMPLE_FUNCTION_ADDRESS = "1006420";

    protected ProgramBuilder builder;
    protected Program program;

    @Before
    public void setUp() throws Exception
    {
        builder = initProgBuilder();
        program = builder.getProgram();
    }

    @After
    public void tearDown() throws Exception
    {
        builder.dispose();
    }

    protected Address addr(ProgramBuilder progBuilder, String addressString)
    {
        return progBuilder.addr(addressString);
    }

    protected Function getSimpleFunction(ProgramBuilder progBuilder)
    {
        Address funcAddress = addr(progBuilder, SIMPLE_FUNCTION_ADDRESS);
        Program prog = progBuilder.getProgram();
        Function simpleFunction = prog.getFunctionManager().getFunctionAt(funcAddress);
        assertTrue(simpleFunction != null);

        return simpleFunction;
    }

    protected ProgramBuilder getProgramBuilderCopy() throws Exception
    {
        return initProgBuilder();
    }

    private ProgramBuilder initProgBuilder() throws Exception
    {
        ProgramBuilder progBuilder =
            new ProgramBuilder("sample", ProgramBuilder._X86, null);
        progBuilder.createMemory(".text", "0x01001000", 0x6600);

        buildSimpleFunction(progBuilder);

        return progBuilder;
    }

    private void buildSimpleFunction(ProgramBuilder progBuilder) throws Exception
    {
        // Instructions inside functions:
        // PUSH EBP
        // COPY
        // INT_SUB
        // STORE
        // MOV EBP,ESP
        // COPY
        // PUSH -0x1
        // COPY
        // INT_SUB
        // STORE
        // PUSH 0x1001888
        // COPY
        // INT_SUB
        // STORE
        // PUSH 0x10065d0
        // COPY
        // INT_SUB
        // STORE
        // MOV EAX,FS:[0x0]
        // INT_ADD
        // LOAD
        // COPY
        // PUSH EAX
        // COPY
        // INT_SUB
        // STORE
        // MOV dword ptr FS:[0x0],ESP
        // INT_ADD
        // COPY
        // STORE
        // ADD ESP,-0x68
        // INT_CARRY
        // INT_SCARRY
        // INT_ADD
        // INT_SLESS
        // INT_EQUAL
        // INT_AND
        // POPCOUNT
        // INT_AND
        // INT_EQUAL
        // PUSH EBX
        // COPY
        // INT_SUB
        // STORE
        // PUSH ESI
        // COPY
        // INT_SUB
        // STORE
        // PUSH EDI
        // COPY
        // INT_SUB
        // STORE
        // MOV dword ptr [EBP + -0x18],ESP
        // INT_ADD
        // COPY
        // STORE
        // MOV dword ptr [EBP + -0x4],0x0
        // INT_ADD
        // COPY
        // STORE
        // PUSH 0x2
        // COPY
        // INT_SUB
        // STORE
        // CALL dword ptr [0x01001160]
        // COPY
        // INT_SUB
        // STORE
        // CALLIND
        // ADD ESP,0x4
        // INT_CARRY
        // INT_SCARRY
        // INT_ADD
        // INT_SLESS
        // INT_EQUAL
        // INT_AND
        // POPCOUNT
        // INT_AND
        // INT_EQUAL
        // MOV dword ptr [0x01009938],0xffffffff
        // COPY
        // MOV dword ptr [0x0100993c],0xffffffff
        // COPY
        // CALL dword ptr [0x00000000]
        // COPY
        // INT_SUB
        // STORE
        // CALLIND

        Program prog = progBuilder.getProgram();

        progBuilder.createEntryPoint("0x1006420", "entry");
        progBuilder.setBytes(
            "0x1006420",
            "55 8b ec 6a ff 68 88 18 00 01 68 d0 65 00 01 64 a1 00 00 00 00 50 "
                + "64 89 25 00 00 00 00 83 c4 98 53 56 57 89 65 e8 c7 45 fc 00 00 00 00 6a 02 ff 15 60 "
                + "11 00 01 83 c4 04 c7 05 38 99 00 01 ff ff ff ff c7 05 3c 99 00 01 ff ff ff ff ff 15 ");

        Function entry = progBuilder.createFunction("0x1006420");

        int transID = prog.startTransaction("Add simple func");
        entry.setBody(new AddressSet(program, addr(progBuilder, "0x1006420"),
                                     addr(progBuilder, "0x100646E")));
        prog.endTransaction(transID, true);

        progBuilder.disassemble(new AddressSet(program, addr(progBuilder, "0x1006420"),
                                               addr(progBuilder, "0x010065aa")));
        progBuilder.createLabel("0x1006420", "simple");
    }
}
