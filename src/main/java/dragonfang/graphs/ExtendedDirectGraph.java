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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.util.graph.DirectedGraph;
import ghidra.util.graph.Vertex;

public abstract class ExtendedDirectGraph extends DirectedGraph {

	protected Map<Object, Vertex> vertexMap;

	public enum ExtDirectGraphType {
		CALL_GRAPH, CONTROL_FLOW_GRAPH
	}

	private ExtDirectGraphType type;

	public ExtendedDirectGraph(ExtDirectGraphType type, int vertexCapacity, int edgeCapacity) {
		super(vertexCapacity, edgeCapacity);
		this.type = type;
		this.vertexMap = new HashMap<Object, Vertex>();
	}

	public ExtendedDirectGraph(ExtDirectGraphType type) {
		super();
		this.type = type;
		this.vertexMap = new HashMap<Object, Vertex>();
	}

	public ExtDirectGraphType getType() {
		return type;
	}

	/**
	 * Returns the vertex associated with the passed object.
	 * 
	 * @param obj The referent object of the vertex.
	 * @return The corresponding vertex.
	 */
	public Vertex getVertex(Object obj) {

		return vertexMap.get(obj);
	}

	/**
	 * Returns the vertex associated with the passed object.
	 * 
	 * @param obj The referent object of the vertex.
	 * @return The corresponding vertex.
	 */
	public Set<Map.Entry<Object, Vertex>> getVertexEntrySet() {

		return vertexMap.entrySet();
	}

	@Override
	public boolean add(Vertex v) {

		vertexMap.put(v.referent(), v);
		return super.add(v);
	}

	@Override
	public boolean remove(Vertex v) {

		vertexMap.remove(v.referent());
		return super.remove(v);
	}
}
