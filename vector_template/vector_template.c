#include "vector_template.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct vector *vector_create( void ) {

	struct vector *v = malloc( sizeof(struct vector) );
	v->count = 0;
	v->size = 0;
	v->elems = NULL;
	v->empty_index = -1;
	return v;

}

void vector_add( struct vector *v, void *nel ) {

	assert( v != NULL );

	int place = v->size;

	if( v->elems == NULL ) {
		v->elems = malloc( sizeof(void *) );
		++v->size;
	} else if( v->empty_index >= 0 ) {
		place = v->empty_index;
		v->empty_index = -1;
	} else {
		++v->size;
		v->elems = realloc( v->elems, (v->size) * sizeof(void *) );
	}

	v->elems[place] = nel;
	++v->count;

}

/*
	Move all elems by one.
	[start][1][2] -> [NULL][start][1][2]
*/
static void vector_move_elems( struct vector *v, int start_pos ) {

	assert( v != NULL && start_pos >= 0 );

	if( v->empty_index > start_pos ) v->empty_index++;

	int i;
	for( i = v->size-1; i > start_pos ; i-- ) {
		v->elems[i] = v->elems[i-1];
	}
	v->elems[start_pos] = NULL;

}

void vector_insert( struct vector *v, void *nel, int index ) {

	assert( v != NULL && index >= 0 );

	if( index == v->empty_index ) v->empty_index = -1;

	if( v->elems == NULL ) { // vector empty, alloc to index+1

		v->elems = calloc( 1, (index+1) * sizeof(void *) );
		v->size = index+1;

	} else if( index >= v->size ) { // index >= size of vector, resize to index+1

		v->elems = realloc( v->elems, (index+1) * sizeof(void *) );

		int i;
		for( i = v->size; i < index+1; i++ ) v->elems[i] = NULL; // zero newly allocated part of vector

		v->size = index+1;

	} else if( v->elems[index] != NULL ) { // if not empty place, resize

		++v->size;
		v->elems = realloc( v->elems, (v->size) * sizeof(void *) );
		vector_move_elems( v, index );

	}

	v->elems[index] = nel;
	++v->count;

}

void vector_swap( struct vector *v, int index_1, int index_2 ) {

	assert( v != NULL && index_1 >= 0 && index_2 >= 0 );

	if( v == NULL || index_1 == index_2 ) return;

	void *tmp = v->elems[index_1];
	v->elems[index_1] = v->elems[index_2];
	v->elems[index_2] = tmp;

}

void *vector_get( struct vector *v, int index ) {

	assert( v != NULL && index >= 0 );
	
	return v->elems[index];

}

void vector_delete_el( struct vector *v, int index, void (*free_elem)(void *) ) {

	assert( v != NULL && v->elems != NULL && index >= 0 );

	if( free_elem != NULL ) (*free_elem)( v->elems[index] );

	v->elems[index] = NULL;
	v->empty_index = index;
	--v->count;

}

void vector_shrink_to_fit( struct vector *v ) {

	assert( v != NULL );

	v->empty_index = -1;

	void **v_copy = malloc( v->count * sizeof(void *) );
	int i = 0, j = 0;
	for( i = 0; i < v->size; i++ ) {
		if( v->elems[i] != NULL ) {
			v_copy[j] = v->elems[i];
			j++;
		}
	}

	v->size = v->count;
	free( v->elems );
	v->elems = v_copy;

}

void vector_map( struct vector *v, void (*func)(void *param) ) {

	assert( v != NULL && func != NULL );

	int i = 0;
	for( i = 0; i < v->size; ++i ) {
		func( v->elems[i] );
	}

}

int vector_search( struct vector *v, void *what, int (*el_cmp)( void *el1, void *el2 ) ) {

	assert( v != NULL && el_cmp != NULL );
	
	int i = 0;
	for( i = 0; i < v->size; ++i ) {
		if( v->elems[i] != NULL ) { // Ommit deleted elems.
			if( el_cmp( what, v->elems[i] ) > 0 ) {
				return i;
			}
		}
	}
	
	return -1; // Element not found.

}

void vector_free( struct vector **v, void (*free_elem)(void *) ) {

	assert( v != NULL && *v != NULL );

	int i;
	for( i = 0; i < (*v)->size; i++ ) {
		if( free_elem != NULL ) (*free_elem)( (*v)->elems[i] );
		(*v)->elems[i] = NULL;
	}

	free( (*v)->elems ); (*v)->elems = NULL;
	free( *v ); *v = NULL;

}
