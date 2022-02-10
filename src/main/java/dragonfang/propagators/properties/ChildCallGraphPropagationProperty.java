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

package dragonfang.propagators.properties;

import java.util.HashSet;
import java.util.Set;

import dragonfang.graphs.CallGraph;
import dragonfang.graphs.wrapper.ExtendedDirectGraphWrapper;
import ghidra.program.model.listing.Function;
import ghidra.util.graph.Vertex;

public class ChildCallGraphPropagationProperty extends AbstractPropagationProperty {

    private ExtendedDirectGraphWrapper callGraphWarapper;

    public ChildCallGraphPropagationProperty(
        ExtendedDirectGraphWrapper callGraphWarapper) {
        this.callGraphWarapper = callGraphWarapper;
    }

    @Override
    public Set<Function> getPropagatedFuncs(Function function,
                                            Set<Function> allCandidateSet) {

        Set<Function> propFuncSet = new HashSet<Function>();

        CallGraph callGraph = (CallGraph) callGraphWarapper.getGraph();

        Vertex matchedVertex  = callGraph.getVertex(function);
        Set<Vertex> vertexSet = callGraph.getChildren(matchedVertex);

        for (Vertex vertex : vertexSet)
            propFuncSet.add((Function) vertex.referent());

        return processCandidateFunctions(propFuncSet, allCandidateSet);
    }

    @Override
    public String getName() {
        return "Child Call Graph Propagation Property";
    }
}
