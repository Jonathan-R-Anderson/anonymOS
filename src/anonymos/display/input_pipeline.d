module anonymos.display.input_pipeline;

/// Minimal input event representation so higher-level components can describe
/// the flow of keyboard/mouse data without tying directly into hardware yet.
struct InputEvent
{
    enum Type { unknown, keyDown, keyUp, pointerMove, buttonDown, buttonUp, scroll }
    Type type;
    int  data1;
    int  data2;
    int  data3;
}

/// Circular buffer used to stage input events before dispatching to windows.
struct InputQueue
{
    enum size_t capacity = 32;
    InputEvent[capacity] events;
    size_t head;
    size_t tail;
}

/// Push an event if there is capacity.
bool enqueue(ref InputQueue queue, InputEvent event) @nogc nothrow
{
    const size_t nextTail = (queue.tail + 1) % InputQueue.capacity;
    if (nextTail == queue.head)
    {
        return false;
    }

    queue.events[queue.tail] = event;
    queue.tail = nextTail;
    return true;
}

/// Pop the next event from the queue.
bool dequeue(ref InputQueue queue, ref InputEvent event) @nogc nothrow
{
    if (queue.head == queue.tail)
    {
        return false;
    }

    event = queue.events[queue.head];
    queue.head = (queue.head + 1) % InputQueue.capacity;
    return true;
}

/// Returns true when there are events waiting.
bool hasEvents(const InputQueue* queue) @nogc nothrow
{
    return queue !is null && queue.head != queue.tail;
}
