/*
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
package nz.gen.coffee.ghidra.string;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;

import ghidra.program.model.mem.MemBuffer;
import ghidra.util.task.TaskMonitor;

public class MemBufferIterator implements Iterator<byte[]> {
    
    private static final int BUFF_SIZE = 4096;
    
    private final TaskMonitor taskMonitor;
    private final MemBuffer memBuffer;

    private long remaining;
    private int offset = 0;
    private byte[] next = null;
    
    public MemBufferIterator(MemBuffer memBuffer, long length, TaskMonitor taskMonitor) {
        this.memBuffer = Objects.requireNonNull(memBuffer);
        this.remaining = length;
        this.taskMonitor = taskMonitor;
        getNext();
    }
    
    public void getNext() {
        if (taskMonitor != null && taskMonitor.isCancelled()) {
            next = null;
            return;
        }
        int bytesToRead = (int) Math.min(BUFF_SIZE, remaining);
        byte[] nextBuffer = new byte[bytesToRead];
        int bytesRead = memBuffer.getBytes(nextBuffer, offset);
        if (bytesRead == 0) {
            next = null;
            return;
        }
        remaining -= bytesRead;
        offset += bytesRead;
        if (bytesRead == bytesToRead) {
            next = nextBuffer;
        } else {
            next = new byte[bytesToRead];
            System.arraycopy(nextBuffer, 0, next, 0, bytesRead);
        }
    }

    @Override
    public boolean hasNext() {
        return next != null;
    }

    @Override
    public byte[] next() {
        if (next == null) {
            throw new NoSuchElementException();
        }
        try {
            taskMonitor.incrementProgress(next.length);
            return next;
        } finally {
            getNext();
        }
    }

}
