export default {
  async registerPublic(ctx) {
    const { h } = ctx.Vue
    ctx.addPublicRoute({
      path: '/public/uitest',
      name: 'tec-tac-uitest-public',
      meta: { title: 'UI Test Public' },
      component: {
        name: 'TecTacUiTestPublic',
        setup() {
          return () => h('section', [
            h('div', { class: 'phead' }, [
              h('div', [
                h('span', { class: 'eyebrow' }, 'PUBLIC EXTENSION PAGE'),
                h('h1', 'UI Test Public'),
                h('p', 'This route was registered before Tactical authentication and is intentionally accessible without a Tactical session.'),
              ]),
            ]),
            h('article', { class: 'card' }, [
              h('div', { class: 'cardhead' }, [
                h('h3', 'Anonymous runtime'),
                h('span', { class: 'pill ok' }, 'PUBLIC'),
              ]),
              h('dl', { class: 'kvlist' }, [
                h('dt', 'Module'), h('dd', { class: 'mono' }, ctx.descriptor.id),
                h('dt', 'Base path'), h('dd', { class: 'mono' }, ctx.descriptor.public.base_path),
                h('dt', 'Authentication'), h('dd', 'Not required for this UI route'),
              ]),
            ]),
          ])
        },
      },
    })
  },
}
