package tunnel

import "sync"

type Identificable interface {
	GetID() int64
}

type QueueItem[Type Identificable] struct {
	Priority int
	Value    Type
}

type Queue[Type Identificable] struct {
	queue             []*QueueItem[Type]
	cap               int
	waitPush, waitPop chan int
	mtx               sync.Mutex
}

func NewQueue[Type Identificable](cap int) *Queue[Type] {
	return &Queue[Type]{
		cap:      cap,
		waitPush: make(chan int),
		waitPop:  make(chan int),
		queue:    make([]*QueueItem[Type], 0, cap),
	}
}

func (q *Queue[Type]) repriorize(id int64, newPrior int) {

	// Encontrar el índice del elemento con el ID dado
	index := -1
	for i := 0; i < len(q.queue); i++ {
		if q.queue[i].Value.GetID() == id {
			index = i
			break
		}
	}

	// Si el elemento no se encuentra, no hacer nada
	if index == -1 {
		return
	}

	// Actualizar la prioridad del elemento
	q.queue[index].Priority = newPrior

	// Hundir el elemento para mantener la propiedad de heap
	for i := index; i > 0; {
		parent := (i - 1) / 2
		if q.queue[parent].Priority >= q.queue[i].Priority {
			break
		}
		q.queue[parent], q.queue[i] = q.queue[i], q.queue[parent]
		i = parent
	}

	// Subir el elemento para mantener la propiedad de heap
	for i := index; i < len(q.queue); {
		left := 2*i + 1
		right := 2*i + 2
		largest := i
		if left < len(q.queue) && q.queue[left].Priority > q.queue[largest].Priority {
			largest = left
		}
		if right < len(q.queue) && q.queue[right].Priority > q.queue[largest].Priority {
			largest = right
		}
		if largest != i {
			q.queue[i], q.queue[largest] = q.queue[largest], q.queue[i]
			i = largest
		} else {
			break
		}
	}
}

func (q *Queue[Type]) PushItem(item *QueueItem[Type]) {
	q.mtx.Lock()
	if len(q.queue) == q.cap {
		q.mtx.Unlock()
		<-q.waitPop
		q.mtx.Lock()
	}
	defer q.mtx.Unlock()

	// Añadir el nuevo elemento al final del slice
	q.queue = append(q.queue, item)

	// Subir el elemento para mantener la propiedad de heap
	i := len(q.queue) - 1
	for i > 0 {
		parent := (i - 1) / 2
		if q.queue[parent].Priority <= q.queue[i].Priority {
			break
		}
		// Intercambiar el elemento con su padre
		q.queue[parent], q.queue[i] = q.queue[i], q.queue[parent]
		i = parent
	}
	select {
	case q.waitPush <- 0:
	default:
	}
}

func (q *Queue[Type]) PopItem() *QueueItem[Type] {
	q.mtx.Lock()
	if len(q.queue) == 0 {
		q.mtx.Unlock()
		<-q.waitPush
		q.mtx.Lock()
	}
	defer q.mtx.Unlock()

	if len(q.queue) == 0 {
		return nil
	}

	// Guardar el elemento con la mayor prioridad
	max := q.queue[0]

	// Mover el último elemento al inicio
	q.queue[0] = q.queue[len(q.queue)-1]
	q.queue = q.queue[:len(q.queue)-1]

	// Hundir el elemento para mantener la propiedad de heap
	i := 0
	for {
		left := 2*i + 1
		right := 2*i + 2
		largest := i

		if left < len(q.queue) && q.queue[left].Priority > q.queue[largest].Priority {
			largest = left
		}
		if right < len(q.queue) && q.queue[right].Priority > q.queue[largest].Priority {
			largest = right
		}
		if largest != i {
			q.queue[i], q.queue[largest] = q.queue[largest], q.queue[i]
			i = largest
		} else {
			break
		}
	}
	q.repriorize(max.Value.GetID(), max.Priority-1)
	select {
	case q.waitPop <- 0:
	default:
	}
	return max
}
