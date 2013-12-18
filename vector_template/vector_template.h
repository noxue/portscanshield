#ifndef __VECTOR_TEMPLATE_H__
#define __VECTOR_TEMPLATE_H__

struct vector {
	int count; //< Number of elems in vector.
	int size; //< Size of vector (greater than count after vector_delete_el())
	void **elems;
	int empty_index; //< After delete, deleted elem index is placed here for more efficient vector_add().
};

/*!
	\brief Creates new vector.
	\return New vector pointer.
*/
struct vector *vector_create( void );

/*!
	\brief Add new element to the vector.
	\param v Vector struct pointer.
	\param nel New elem pointer.
*/
void vector_add( struct vector *v, void *nel );

/*!
	\brief Add elem nel to vector at specified index.
	\param v Vector struct pointer.
	\param nel New elem pointer.
	\param index Where to place new elem. If index is bigger than vector size, vector is resized.
*/
void vector_insert( struct vector *v, void *nel, int index );

/*!
	\brief Swap two elems.
	\param v Vector struct pointer.
	\param index_1 Index of the elem to swap.
	\param index_2 Index of the elem to swap.
*/
void vector_swap( struct vector *v, int index_1, int index_2 );

/*!
	\brief Return elem at index.
	\param v Vector struct pointer.
	\param index Index of elem to return.
	\return Pointer to elem located at specified index.
*/
void *vector_get( struct vector *v, int index );

/*!
	\brief Delete elem from vector.
	\param v Vector struct pointer.
	\param index Index of elem to delete.
	\param free_elem Function to free vector element (if neccessary, if not NULL).
*/
void vector_delete_el( struct vector *v, int index, void (*free_elem)(void *) );

/*!
	\brief Shrink vector to minimal size. Can be called after several vector_delete(...).
	\param v Vector struct pointer.
*/
void vector_shrink_to_fit( struct vector *v );

/*!
	\brief Execute specified function on every vector elem.
	\param v Vector struct pointer.
	\param func Function that will be executed on every vector elem.
*/
void vector_map( struct vector *v, void (*func)(void *param) );

/*!
	\brief Search for "what" in vector.
	\param v Vector struct pointer.
	\param what Pointer to element to find.
	\param el_cmp Vector element compare function. Return value should be greater than 0 if el1 is equal to el2.
	\return Returns index of found element, or -1 if element not in vector.
*/
int vector_search( struct vector *v, void *what, int (*el_cmp)( void *el1, void *el2 ) );

/*!
	\brief Delete & free vector.
	\param v Pointer to vector struct pointer.
	\param free_elem Function to free vector element (if neccessary, if not NULL).
*/
void vector_free( struct vector **v, void (*free_elem)(void *) );

#endif
