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
layout(binding=0) uniform sampler2D tex0;
layout(binding=1) uniform sampler2D tex1;
layout(location=0) in vec2 uv;
layout(location=0) out vec4 color;
void main() {
    if (p.options.x<0.5) color=p.tint;
    else if (p.options.x<1.5) {
        color=texture(tex0,uv)*p.tint;
        if (p.options.y<0.5) color.rgb*=color.a;
        else color.rgb*=p.tint.a;
    } else if (p.options.x<2.5) {
        float a=texture(tex0,uv).r*p.tint.a;
        color=vec4(p.tint.rgb*a,a);
    } else {
        vec2 step=p.viewport.zw;
        vec2 luma=clamp(uv,step*0.5,p.uvrect.zw-step*0.5);
        vec2 chroma=clamp(uv+p.options.zw,step,p.uvrect.zw-step);
        vec4 yuv=vec4(texture(tex0,luma).r,texture(tex1,chroma).rg,1.0);
        color=vec4(dot(p.row0,yuv),dot(p.row1,yuv),dot(p.row2,yuv),1.0);
    }
    if (p.options.x<0.5) color.rgb*=color.a;
}
