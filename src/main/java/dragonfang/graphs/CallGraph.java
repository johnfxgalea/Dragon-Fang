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

package dragonfang.graphs;

import dragonfang.entities.Entity;
import dragonfang.entities.Entity.GranularityType;
import ghidra.util.graph.Vertex;

public class CallGraph extends ExtendedDirectGraph
{

    public CallGraph(int vertexCapacity, int edgeCapacity)
    {
        super(ExtDirectGraphType.CALL_GRAPH, vertexCapacity, edgeCapacity);
    }

    public CallGraph()
    {
        super(ExtDirectGraphType.CALL_GRAPH);
    }

    @Override
    public Vertex getVertex(Object obj)
    {
        Entity entity = (Entity) obj;
        if (entity.getGranularity() != GranularityType.FUNCTION) {
            throw new IllegalArgumentException(
                "Invalid feature vector size passed as param.");
        }
        return vertexMap.get(obj);
    }
}
