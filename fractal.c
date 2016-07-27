// Written by nue - December 2014
// gcc5 -c -o fractal.o fractal2.c -Wall `sdl-config --cflags` && gcc5 `sdl-config --libs` -lSDL -lGL -lm -lstdc++ -o fractal2 fractal.o && ./fractal2

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <complex.h>
#include <SDL/SDL.h>

#define MAX_Y 720
#define MAX_X 1280
#define DEPTH 1000

void DrawPix(SDL_Surface *display, int x, int y, Uint8 R, Uint8 G, Uint8 B){
  Uint32 col = SDL_MapRGB(display->format, R, G, B);
  Uint32 *bufp;
  bufp = (Uint32 *)display->pixels + y*display->pitch/4 + x;
  *bufp = col;
}

int main(int argc, char **argv){
  SDL_Surface *screen = NULL;
  SDL_Init(SDL_INIT_EVERYTHING);
  screen = SDL_SetVideoMode(MAX_X, MAX_Y, 32, SDL_SWSURFACE);
  double complex total_val;
  float x, y;
  
  for(x=0;x<MAX_X;x++){
    for(y=0;y<MAX_Y;y++){
      long int itter = 0;
      total_val = 0.0;

      for(;itter<DEPTH && (creal(total_val) > -2.5 && creal(total_val) < 1
          && cimag(total_val) < 1 && cimag(total_val) > -1);itter++){
        float scale_x = x/(MAX_X/3.5); // Scale x.
        if(scale_x < 2.5 && scale_x != 0.0)
          scale_x = (2.5-scale_x)*-1;
        else if(scale_x >= 2.5)
          scale_x -= 2.5;
          
        float scale_y = y/(MAX_Y/2); // Scale y.
        if(scale_y < 1.0 && scale_y != 0.0)
          scale_y = (1.0 - scale_y)*-1;    
        else if(scale_y >= 1.0)
          scale_y -= 1.0;
        total_val = (total_val*total_val)+scale_x+(scale_y*I);
      }

      if(itter == DEPTH) // Non escaped value.
        DrawPix(screen, x, y, 0, 0, 0);
      else{ // A value that has escaped.
        int B = 255 - itter%255;
        DrawPix(screen, x, y, (255-B), 0, B);
      }
    }
  }
  SDL_Flip(screen);  
  SDL_Delay(10000);
}
