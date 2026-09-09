#version 460
layout(std140,binding=0) uniform Params {
    vec4 destination;
    vec4 uvrect;
    vec4 tint;
    vec4 viewport;
    vec4 row0;
    vec4 row1;
    vec4 row2;
    vec4 options;
} p;
layout(location=0) out vec2 uv;
void main() {
    const vec2 corners[6]=vec2[6](vec2(0,0),vec2(1,0),vec2(0,1),vec2(0,1),vec2(1,0),vec2(1,1));
    vec2 q=corners[gl_VertexID];
    vec2 position=p.destination.xy+q*p.destination.zw;
    vec2 ndc=position/p.viewport.xy*2.0-1.0;
    gl_Position=vec4(ndc.x,-ndc.y,0.0,1.0);
    uv=p.uvrect.xy+q*p.uvrect.zw;
}
